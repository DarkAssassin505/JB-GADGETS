-- =====================================================================
-- JB Gadgets Store - the shop's key, and whose log is whose
-- =====================================================================
-- Two changes, both about the line between the platform and the shop.
--
--   1. Joseph's activity log is his. He sees what his own team did; he
--      does not see what the owner did. The owner still sees all of it.
--
--   2. The owner cannot change the shop's stock on his own. Joseph sets
--      a key, keeps it, and the owner has to be given it before any
--      stock, price or cost can be touched. Joseph needs no key for his
--      own shop - pricing and costs stay his to run alone.
--
-- Worth being plain about what this is. The owner holds the database
-- account, so with enough determination he could change the key itself
-- from the Supabase dashboard. What this stops is a quiet change made
-- through the app: a stock change by the owner only happens with the
-- key, and when it does, the log records it as such. A refused attempt
-- is not recorded - the refusal rolls the whole thing back, the log
-- entry with it - so this is a lock on the front door, not a vault.
-- =====================================================================

create extension if not exists pgcrypto;


-- ---------------------------------------------------------------------
-- 1. "Admin" meaning Joseph, not the owner
-- ---------------------------------------------------------------------
create or replace function public.is_shop_admin()
returns boolean
language sql
stable
security definer
set search_path = public
as $$
    select exists (
        select 1 from public.profiles
        where id = auth.uid() and is_active and role = 'admin'
    );
$$;


-- ---------------------------------------------------------------------
-- 2. The key itself
-- ---------------------------------------------------------------------
-- Only the hash is kept, so the key cannot be read back out of here by
-- anyone, the owner included.

create table if not exists public.shop_key (
    id       boolean primary key default true check (id),
    key_hash text,
    set_by   uuid references public.profiles (id) on delete set null,
    set_at   timestamptz
);
insert into public.shop_key (id) values (true) on conflict (id) do nothing;

alter table public.shop_key enable row level security;

-- No policy for anyone. The table is reached only through the functions
-- below, which decide who may do what.
drop policy if exists shop_admin_all on public.shop_key;
revoke all on public.shop_key from anon, authenticated;


create or replace function public.shop_key_set(p_new_key text, p_current_key text default null)
returns jsonb
language plpgsql
security definer
set search_path = public, extensions
as $$
declare
    v_existing text;
begin
    if not public.is_shop_admin() then
        raise exception 'Only the shop admin sets the shop key.';
    end if;
    if length(coalesce(p_new_key, '')) < 8 then
        raise exception 'The shop key needs at least 8 characters.';
    end if;

    select key_hash into v_existing from public.shop_key where id;

    -- Changing an existing key needs the old one, so a borrowed screen
    -- cannot be used to lock the shop out of its own stock.
    if v_existing is not null then
        if p_current_key is null or v_existing <> crypt(p_current_key, v_existing) then
            raise exception 'The current shop key does not match.';
        end if;
    end if;

    update public.shop_key
    set key_hash = crypt(p_new_key, gen_salt('bf')),
        set_by = auth.uid(), set_at = now()
    where id;

    perform public.audit(
        case when v_existing is null then 'shop key set' else 'shop key changed' end,
        'shop key', null, null, null);

    return jsonb_build_object('ok', true);
end;
$$;


-- Says only whether one exists, never what it is.
create or replace function public.shop_key_is_set()
returns boolean
language sql
stable
security definer
set search_path = public
as $$
    select public.is_admin() and exists (select 1 from public.shop_key where id and key_hash is not null);
$$;


-- The test the stock functions run. An admin passes without one; the
-- owner has to produce it.
create or replace function public.shop_key_ok(p_key text)
returns boolean
language plpgsql
stable
security definer
set search_path = public, extensions
as $$
declare
    v_hash text;
begin
    if public.is_shop_admin() then
        return true;                       -- the shop runs its own stock
    end if;
    if not public.is_owner() then
        return false;
    end if;

    select key_hash into v_hash from public.shop_key where id;

    if v_hash is null then
        raise exception 'The shop has not set its key yet. Ask the shop admin to set one before stock can be changed from here.';
    end if;
    if p_key is null or btrim(p_key) = '' then
        raise exception 'This shop''s stock is locked. Ask the shop admin for the shop key.';
    end if;
    if v_hash <> crypt(p_key, v_hash) then
        raise exception 'That shop key is not right.';
    end if;
    return true;
end;
$$;


-- ---------------------------------------------------------------------
-- 3. Stock changes ask for it
-- ---------------------------------------------------------------------
drop function if exists public.admin_save_item(uuid, text, text, text, numeric, numeric, integer, numeric, numeric);
drop function if exists public.admin_delete_item(uuid);
drop function if exists public.admin_import_items(jsonb);

create or replace function public.admin_save_item(
    p_id        uuid    default null,
    p_name      text    default null,
    p_category  text    default null,
    p_condition text    default null,
    p_cost      numeric default 0,
    p_selling   numeric default 0,
    p_stock     integer default 0,
    p_first     numeric default null,
    p_weekly    numeric default null,
    p_shop_key  text    default null
)
returns public.inventory
language plpgsql
security definer
set search_path = public, extensions
as $$
declare
    v_old  public.inventory%rowtype;
    v_new  public.inventory%rowtype;
    v_diff jsonb;
    v_by_owner boolean := public.is_owner();
begin
    if not public.is_admin() then
        raise exception 'Not allowed: only the owner or an admin can change stock.';
    end if;
    perform public.shop_key_ok(p_shop_key);
    if coalesce(btrim(p_name), '') = '' then
        raise exception 'An item needs a name.';
    end if;

    if p_id is null then
        insert into public.inventory (name, category, condition, cost_price,
                                      selling_price, stock, first_payment, weekly_payment)
        values (btrim(p_name), p_category, p_condition, coalesce(p_cost, 0),
                coalesce(p_selling, 0), coalesce(p_stock, 0), p_first, p_weekly)
        returning * into v_new;

        perform public.audit('item added', 'inventory', v_new.id::text, v_new.name,
                 jsonb_build_object('stock', v_new.stock, 'selling_price', v_new.selling_price,
                                    'with_shop_key', v_by_owner));
        return v_new;
    end if;

    select * into v_old from public.inventory where id = p_id for update;
    if not found then
        raise exception 'That item is no longer in the catalogue.';
    end if;

    update public.inventory
    set name = btrim(p_name), category = p_category, condition = p_condition,
        cost_price = coalesce(p_cost, 0), selling_price = coalesce(p_selling, 0),
        stock = coalesce(p_stock, 0), first_payment = p_first, weekly_payment = p_weekly,
        updated_at = now()
    where id = p_id
    returning * into v_new;

    v_diff := public.audit_diff(to_jsonb(v_old), to_jsonb(v_new),
        array['name','category','condition','cost_price','selling_price',
              'stock','first_payment','weekly_payment']);

    if v_diff <> '{}'::jsonb then
        if v_by_owner then
            v_diff := v_diff || jsonb_build_object('with_shop_key', true);
        end if;
        perform public.audit(
            case when v_diff ? 'stock' and (select count(*) from jsonb_object_keys(v_diff - 'with_shop_key')) = 1
                 then 'stock adjusted by hand' else 'item changed' end,
            'inventory', v_new.id::text, v_new.name, v_diff);
    end if;
    return v_new;
end;
$$;


create or replace function public.admin_delete_item(p_id uuid, p_shop_key text default null)
returns void
language plpgsql
security definer
set search_path = public, extensions
as $$
declare
    v_old public.inventory%rowtype;
begin
    if not public.is_admin() then
        raise exception 'Not allowed: only the owner or an admin can remove stock.';
    end if;
    perform public.shop_key_ok(p_shop_key);

    select * into v_old from public.inventory where id = p_id;
    if not found then return; end if;

    delete from public.inventory where id = p_id;

    perform public.audit('item removed', 'inventory', v_old.id::text, v_old.name,
             jsonb_build_object('stock_at_removal', v_old.stock,
                                'selling_price', v_old.selling_price,
                                'with_shop_key', public.is_owner()));
end;
$$;


create or replace function public.admin_import_items(p_rows jsonb, p_shop_key text default null)
returns integer
language plpgsql
security definer
set search_path = public, extensions
as $$
declare
    v_row   jsonb;
    v_count integer := 0;
begin
    if not public.is_admin() then
        raise exception 'Not allowed: only the owner or an admin can import stock.';
    end if;
    perform public.shop_key_ok(p_shop_key);

    for v_row in select * from jsonb_array_elements(p_rows)
    loop
        insert into public.inventory (name, category, condition, cost_price,
                                      selling_price, stock, first_payment, weekly_payment)
        values (btrim(v_row ->> 'name'), v_row ->> 'category', v_row ->> 'condition',
                coalesce((v_row ->> 'cost_price')::numeric, 0),
                coalesce((v_row ->> 'selling_price')::numeric, 0),
                coalesce((v_row ->> 'stock')::integer, 0),
                nullif(v_row ->> 'first_payment', '')::numeric,
                nullif(v_row ->> 'weekly_payment', '')::numeric);
        v_count := v_count + 1;
    end loop;

    perform public.audit('stock imported', 'inventory', null, null,
             jsonb_build_object('items', v_count, 'with_shop_key', public.is_owner()));
    return v_count;
end;
$$;


-- ---------------------------------------------------------------------
-- 4. Joseph's log is Joseph's
-- ---------------------------------------------------------------------
-- He sees his own team's activity. The owner's entries are not hidden
-- on screen; they are not in the answer the database gives.

drop policy if exists admin_read on public.audit_log;
create policy admin_read on public.audit_log
    for select to authenticated
    using (
        public.is_admin()
        and (public.is_owner() or coalesce(actor_role, '') <> 'owner')
    );


-- ---------------------------------------------------------------------
-- 5. Grants
-- ---------------------------------------------------------------------
revoke execute on function public.admin_save_item(uuid, text, text, text, numeric, numeric, integer, numeric, numeric, text) from public, anon;
grant  execute on function public.admin_save_item(uuid, text, text, text, numeric, numeric, integer, numeric, numeric, text) to authenticated;
revoke execute on function public.admin_delete_item(uuid, text)   from public, anon;
grant  execute on function public.admin_delete_item(uuid, text)   to authenticated;
revoke execute on function public.admin_import_items(jsonb, text) from public, anon;
grant  execute on function public.admin_import_items(jsonb, text) to authenticated;

revoke execute on function public.shop_key_set(text, text) from public, anon;
grant  execute on function public.shop_key_set(text, text) to authenticated;
revoke execute on function public.shop_key_is_set()        from public, anon;
grant  execute on function public.shop_key_is_set()        to authenticated;
revoke execute on function public.shop_key_ok(text)        from public, anon;
revoke execute on function public.is_shop_admin()          from public, anon;
grant  execute on function public.is_shop_admin()          to authenticated;

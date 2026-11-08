-- =====================================================================
-- JB Gadgets Store - who runs the shop, and who runs the system
-- =====================================================================
-- Three things change here.
--
--   1. Joseph brings staff on board himself. He can add an admin or a
--      cashier, name them, switch them on and off and change their role
--      - but he can never see, touch or create an owner.
--
--   2. Cashiers have no email address. Each one gets a six-character
--      staff ID instead, and signs in with that. The ID maps to an
--      internal address the login system uses behind the scenes, so the
--      cashier never sees an email anywhere.
--
--   3. The settings split in two. Shop settings - name, location,
--      currency - stay with the admin. Receipt design and the shop's
--      guard rails become the owner's alone, and do not appear on
--      anyone else's screen.
--
-- The owner stays invisible throughout. That was already true of the
-- profiles table; this adds the same rule to everything new.
-- =====================================================================


-- ---------------------------------------------------------------------
-- 1. Staff IDs
-- ---------------------------------------------------------------------
alter table public.profiles
    add column if not exists staff_id   text,
    add column if not exists created_by uuid references public.profiles (id),
    add column if not exists deactivated_at timestamptz;

-- Six characters, upper case, no letters that can be mistaken for digits.
alter table public.profiles drop constraint if exists profiles_staff_id_shape;
alter table public.profiles add constraint profiles_staff_id_shape
    check (staff_id is null or staff_id ~ '^[A-HJ-NP-Z2-9]{6}$');

create unique index if not exists profiles_staff_id_key
    on public.profiles (staff_id) where staff_id is not null;

-- The alphabet leaves out I, O, 0 and 1 so an ID read off a slip of
-- paper cannot be typed wrong.
create or replace function public.generate_staff_id()
returns text
language plpgsql
security definer
set search_path = public
as $$
declare
    v_alphabet constant text := 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
    v_id    text;
    v_tries integer := 0;
begin
    loop
        v_id := '';
        for i in 1..6 loop
            v_id := v_id || substr(v_alphabet, 1 + floor(random() * length(v_alphabet))::int, 1);
        end loop;
        exit when not exists (select 1 from public.profiles where staff_id = v_id);
        v_tries := v_tries + 1;
        if v_tries > 50 then
            raise exception 'Could not find a free staff ID. Try again.';
        end if;
    end loop;
    return v_id;
end;
$$;


-- The app needs an ID before it can create the login, because the
-- login's address is built from the ID. Reserving it properly would need
-- a table of its own; instead the address itself is the reservation,
-- since two people cannot share one. A clash just fails the signup.
create or replace function public.admin_next_staff_id()
returns text
language plpgsql
security definer
set search_path = public
as $$
begin
    if not public.is_admin() then
        raise exception 'Not allowed: only the owner or an admin can add staff.';
    end if;
    return public.generate_staff_id();
end;
$$;


-- ---------------------------------------------------------------------
-- 2. The staff list Joseph sees
-- ---------------------------------------------------------------------
-- The owner is not in it. Not hidden on screen - not in the answer the
-- database gives, so there is nothing to find by looking harder. A
-- cashier has no business with the staff list at all, so it is owner
-- and admin only.

create or replace view public.staff_directory as
    select p.id, p.full_name, p.role, p.staff_id, p.is_active,
           p.created_at, p.deactivated_at,
           u.email,
           (p.id = auth.uid()) as is_me
    from public.profiles p
    join auth.users u on u.id = p.id
    where public.is_admin()
      and (public.is_owner() or p.role <> 'owner');

revoke all on public.staff_directory from public, anon;
grant select on public.staff_directory to authenticated;


-- ---------------------------------------------------------------------
-- 3. Bringing someone on board
-- ---------------------------------------------------------------------
-- The login itself is created by the app; this names the person, gives
-- them a role and switches them on. An admin may create an admin or a
-- cashier. Only the owner is an owner, and nothing here can change that.

create or replace function public.admin_register_staff(
    p_user_id   uuid,
    p_full_name text,
    p_role      text default 'cashier'
)
returns jsonb
language plpgsql
security definer
set search_path = public
as $$
declare
    v_target   public.profiles%rowtype;
    v_staff_id text;
begin
    if not public.is_admin() then
        raise exception 'Not allowed: only the owner or an admin can add staff.';
    end if;
    if p_role not in ('admin', 'cashier') then
        raise exception 'A new member of staff is either an admin or a cashier.';
    end if;
    if coalesce(btrim(p_full_name), '') = '' then
        raise exception 'A new member of staff needs a name.';
    end if;

    select * into v_target from public.profiles where id = p_user_id for update;
    if not found then
        raise exception 'That login does not exist yet.';
    end if;
    if v_target.role = 'owner' then
        raise exception 'That account cannot be changed.';
    end if;

    -- A cashier is known by a staff ID; an admin by their email.
    if p_role = 'cashier' then
        v_staff_id := coalesce(v_target.staff_id, public.generate_staff_id());
    else
        v_staff_id := null;
    end if;

    update public.profiles
    set full_name  = btrim(p_full_name),
        role       = p_role,
        staff_id   = v_staff_id,
        is_active  = true,
        deactivated_at = null,
        created_by = coalesce(created_by, auth.uid())
    where id = p_user_id;

    return jsonb_build_object('id', p_user_id, 'full_name', btrim(p_full_name),
                              'role', p_role, 'staff_id', v_staff_id);
end;
$$;


-- ---------------------------------------------------------------------
-- 4. Changing a role, and switching someone off
-- ---------------------------------------------------------------------
create or replace function public.admin_set_role(p_user_id uuid, p_role text)
returns jsonb
language plpgsql
security definer
set search_path = public
as $$
declare
    v_target   public.profiles%rowtype;
    v_staff_id text;
begin
    if not public.is_admin() then
        raise exception 'Not allowed: only the owner or an admin can change a role.';
    end if;
    if p_role not in ('admin', 'cashier') then
        raise exception 'A role is either admin or cashier.';
    end if;
    if p_user_id = auth.uid() then
        raise exception 'You cannot change your own role.';
    end if;

    select * into v_target from public.profiles where id = p_user_id for update;
    if not found then
        raise exception 'That person is not on the staff list.';
    end if;
    if v_target.role = 'owner' then
        raise exception 'That account cannot be changed.';
    end if;

    -- Moving to cashier earns a staff ID; moving to admin keeps it, so a
    -- cashier promoted and then moved back has the same ID as before.
    v_staff_id := case when p_role = 'cashier'
                       then coalesce(v_target.staff_id, public.generate_staff_id())
                       else v_target.staff_id end;

    update public.profiles
    set role = p_role, staff_id = v_staff_id
    where id = p_user_id;

    return jsonb_build_object('id', p_user_id, 'role', p_role, 'staff_id', v_staff_id);
end;
$$;

create or replace function public.admin_set_active(p_user_id uuid, p_active boolean)
returns jsonb
language plpgsql
security definer
set search_path = public
as $$
declare
    v_target public.profiles%rowtype;
begin
    if not public.is_admin() then
        raise exception 'Not allowed: only the owner or an admin can do that.';
    end if;
    if p_user_id = auth.uid() then
        raise exception 'You cannot switch off your own account.';
    end if;

    select * into v_target from public.profiles where id = p_user_id for update;
    if not found then
        raise exception 'That person is not on the staff list.';
    end if;
    if v_target.role = 'owner' then
        raise exception 'That account cannot be changed.';
    end if;

    update public.profiles
    set is_active = p_active,
        deactivated_at = case when p_active then null else now() end
    where id = p_user_id;

    return jsonb_build_object('id', p_user_id, 'is_active', p_active);
end;
$$;


-- ---------------------------------------------------------------------
-- 5. Receipt design - the owner's alone
-- ---------------------------------------------------------------------
create table if not exists public.receipt_design (
    id            boolean primary key default true check (id),
    header_line   text    not null default 'JB GADGETS STORE',
    subheader     text    not null default 'Lusaka CBD  |  0964 485293',
    footer_text   text    not null default 'Thank you for your business!',
    terms_text    text    not null default 'Weekly plans: payments are due every 7 days from the date above.',
    show_logo     boolean not null default true,
    show_cashier  boolean not null default true,
    show_customer boolean not null default true,
    paper_width   text    not null default '80mm' check (paper_width in ('58mm', '80mm', 'A4')),
    updated_at    timestamptz not null default now()
);

-- Carry over whatever footer the shop is already using. Guarded on the
-- column still being there, because section 7 below drops it - without
-- this the migration would fail the second time it ever ran.
do $$
begin
    if exists (select 1 from information_schema.columns
               where table_schema = 'public' and table_name = 'settings'
                 and column_name = 'receipt_footer') then
        execute $q$
            insert into public.receipt_design (id, footer_text)
            select true, s.receipt_footer from public.settings s
            on conflict (id) do nothing
        $q$;
    end if;
end
$$;
insert into public.receipt_design (id) values (true) on conflict (id) do nothing;

alter table public.receipt_design enable row level security;

drop policy if exists staff_read on public.receipt_design;
drop policy if exists owner_all  on public.receipt_design;

-- Everyone needs to read it to print a receipt. Only the owner sets it.
create policy staff_read on public.receipt_design
    for select to authenticated using (public.is_staff());
create policy owner_all on public.receipt_design
    for all to authenticated using (public.is_owner()) with check (public.is_owner());


-- ---------------------------------------------------------------------
-- 6. The shop's guard rails - also the owner's alone
-- ---------------------------------------------------------------------
create table if not exists public.owner_settings (
    id                   boolean primary key default true check (id),
    max_discount_percent numeric(5,2) not null default 10 check (max_discount_percent between 0 and 100),
    require_nrc_for_hp   boolean not null default true,
    low_stock_threshold  integer not null default 2 check (low_stock_threshold >= 0),
    updated_at           timestamptz not null default now()
);
insert into public.owner_settings (id) values (true) on conflict (id) do nothing;

alter table public.owner_settings enable row level security;

drop policy if exists staff_read on public.owner_settings;
drop policy if exists owner_all  on public.owner_settings;

-- Staff read them because the till has to obey them; only the owner
-- changes them, and the screen to change them is the owner's alone.
create policy staff_read on public.owner_settings
    for select to authenticated using (public.is_staff());
create policy owner_all on public.owner_settings
    for all to authenticated using (public.is_owner()) with check (public.is_owner());


-- ---------------------------------------------------------------------
-- 7. The receipt footer leaves the shop settings
-- ---------------------------------------------------------------------
-- It lived on settings, which an admin may edit. Receipt wording is the
-- owner's, so the column goes and receipt_design holds it instead.
alter table public.settings drop column if exists receipt_footer;


-- ---------------------------------------------------------------------
-- 8. Grants
-- ---------------------------------------------------------------------
revoke execute on function public.generate_staff_id()                        from public, anon;
revoke execute on function public.admin_next_staff_id()                      from public, anon;
grant  execute on function public.admin_next_staff_id()                      to authenticated;
revoke execute on function public.admin_register_staff(uuid, text, text)     from public, anon;
revoke execute on function public.admin_set_role(uuid, text)                 from public, anon;
revoke execute on function public.admin_set_active(uuid, boolean)            from public, anon;

grant  execute on function public.admin_register_staff(uuid, text, text)     to authenticated;
grant  execute on function public.admin_set_role(uuid, text)                 to authenticated;
grant  execute on function public.admin_set_active(uuid, boolean)            to authenticated;
-- generate_staff_id is only ever called by the functions above.

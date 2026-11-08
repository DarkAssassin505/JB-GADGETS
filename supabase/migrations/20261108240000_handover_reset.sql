-- =====================================================================
-- JB Gadgets Store - setting up, and handing over
-- =====================================================================
-- The shop key locked the owner out of stock immediately, which left
-- nobody able to set the shop up in the first place. Two changes fix
-- that and make the handover a deliberate moment rather than an
-- accident.
--
--   1. Until the shop sets its key, the owner may work on stock. That
--      is the setup period: the shop has not claimed its lock yet. The
--      moment Joseph sets a key, the owner needs it, for good.
--
--   2. A reset the owner can run to hand over a clean shop: clear the
--      trading records, or clear everything including stock, customers,
--      repairs and expenses. Staff, settings and the activity log stay.
--      The log stays on purpose - it is the one thing nobody deletes,
--      and the reset itself is written into it.
-- =====================================================================


-- ---------------------------------------------------------------------
-- 1. The setup period
-- ---------------------------------------------------------------------
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

    -- No key yet means the shop has not been handed over. The owner is
    -- still setting it up, so he may work. Everything he does is logged
    -- either way.
    if v_hash is null then
        return true;
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
-- 2. The handover reset
-- ---------------------------------------------------------------------
-- 'trading'    - sales, returns, hire purchase plans and their payments.
--                Stock stays, and the stock sold on un-returned sales is
--                put back, so the counts are right again.
-- 'everything' - the above, plus stock, customers, repairs and expenses.
--                A bare shop, ready for the real list to be loaded.
--
-- Staff, settings, receipt design, the shop rules and the activity log
-- are never touched.

create or replace function public.owner_reset_shop(
    p_scope    text default 'trading',
    p_shop_key text default null
)
returns jsonb
language plpgsql
security definer
set search_path = public, extensions
as $$
declare
    v_sales      integer;
    v_returns    integer;
    v_agreements integer;
    v_items      integer := 0;
    v_customers  integer := 0;
    v_repairs    integer := 0;
    v_expenses   integer := 0;
    v_units      integer := 0;
begin
    if not public.is_owner() then
        raise exception 'Not allowed: only the owner can reset the shop.';
    end if;
    if p_scope not in ('trading', 'everything') then
        raise exception 'Reset either the trading records or everything.';
    end if;
    perform public.shop_key_ok(p_shop_key);

    select count(*) into v_sales      from public.sales;
    select count(*) into v_returns    from public.returns_log;
    select count(*) into v_agreements from public.hp_agreements;

    if p_scope = 'trading' then
        -- Put back what was sold and never returned, so stock is true.
        select coalesce(sum(si.qty), 0) into v_units
        from public.sale_items si
        join public.sales s on s.id = si.sale_id
        where not s.returned and not s.is_test;

        update public.inventory i
        set stock = i.stock + x.qty, updated_at = now()
        from (
            select si.inventory_id, sum(si.qty) as qty
            from public.sale_items si
            join public.sales s on s.id = si.sale_id
            where not s.returned and not s.is_test and si.inventory_id is not null
            group by si.inventory_id
        ) x
        where i.id = x.inventory_id;
    end if;

    delete from public.hp_payments;
    delete from public.hp_agreements;
    delete from public.returns_log;
    delete from public.sale_items;
    delete from public.sales;

    if p_scope = 'everything' then
        select count(*) into v_items     from public.inventory;
        select count(*) into v_customers from public.customers;
        select count(*) into v_repairs   from public.repairs;
        select count(*) into v_expenses  from public.expenses;

        delete from public.inventory;
        delete from public.customers;
        delete from public.repairs;
        delete from public.expenses;
    end if;

    perform public.audit('shop reset for handover', 'shop', null, null,
             jsonb_build_object('scope', p_scope, 'sales', v_sales,
                                'returns', v_returns, 'plans', v_agreements,
                                'items', v_items, 'customers', v_customers,
                                'repairs', v_repairs, 'expenses', v_expenses,
                                'units_restored', v_units));

    return jsonb_build_object('scope', p_scope, 'sales', v_sales, 'returns', v_returns,
                              'plans', v_agreements, 'items', v_items,
                              'customers', v_customers, 'repairs', v_repairs,
                              'expenses', v_expenses, 'units_restored', v_units);
end;
$$;

revoke execute on function public.owner_reset_shop(text, text) from public, anon;
grant  execute on function public.owner_reset_shop(text, text) to authenticated;

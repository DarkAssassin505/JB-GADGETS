-- =====================================================================
-- JB Gadgets Store - support for the connected app
-- =====================================================================
-- Two things the web app needs that the first migration did not cover.
--
-- 1. A sale rung up while the internet is down is held on the device and
--    sent when the connection returns. If the reply to the first attempt
--    is lost, the till retries, and without a guard the same sale would
--    be banked twice. Every sale now carries a reference made on the
--    device, and a repeat of that reference returns the original sale
--    instead of creating a second one.
--
-- 2. Clearing practice transactions. The app cannot delete sales
--    directly - permission to do so is deliberately withheld - so this
--    adds one owner-and-admin-only step that does it properly and puts
--    the stock back.
-- =====================================================================


-- ---------------------------------------------------------------------
-- 1. Sales carry the till's own reference
-- ---------------------------------------------------------------------
alter table public.sales add column if not exists client_ref uuid;

create unique index if not exists sales_client_ref_key
    on public.sales (client_ref) where client_ref is not null;


-- The argument list changes, so the old version is removed first.
drop function if exists public.record_sale(jsonb, text, text, numeric, text, numeric);

create or replace function public.record_sale(
    p_items           jsonb,
    p_customer_name   text default null,
    p_sale_type       text default 'Cash',
    p_discount        numeric default 0,
    p_trade_in_device text default null,
    p_trade_in_value  numeric default 0,
    p_client_ref      uuid default null
)
returns bigint
language plpgsql
security definer
set search_path = public
as $$
declare
    v_sale_id  bigint;
    v_item     jsonb;
    v_row      public.inventory%rowtype;
    v_qty      integer;
    v_subtotal numeric(12,2) := 0;
    v_total    numeric(12,2);
begin
    if not public.is_staff() then
        raise exception 'Not allowed: you are not signed in as staff.';
    end if;
    if p_items is null or jsonb_array_length(p_items) = 0 then
        raise exception 'A sale needs at least one item.';
    end if;

    -- Already banked under this reference? Hand back the original.
    if p_client_ref is not null then
        select id into v_sale_id from public.sales where client_ref = p_client_ref;
        if found then
            return v_sale_id;
        end if;
    end if;

    insert into public.sales (customer_name, sale_type, discount,
                              trade_in_device, trade_in_value, sold_by, client_ref)
    values (nullif(p_customer_name, ''), p_sale_type, coalesce(p_discount, 0),
            nullif(p_trade_in_device, ''), coalesce(p_trade_in_value, 0), auth.uid(), p_client_ref)
    returning id into v_sale_id;

    for v_item in select * from jsonb_array_elements(p_items)
    loop
        v_qty := (v_item ->> 'qty')::integer;

        select * into v_row from public.inventory
        where id = (v_item ->> 'inventory_id')::uuid
        for update;

        if not found then
            raise exception 'That product is no longer in the catalogue.';
        end if;
        if v_row.stock < v_qty then
            raise exception 'Only % left of %, cannot sell %.', v_row.stock, v_row.name, v_qty;
        end if;

        update public.inventory
        set stock = stock - v_qty, updated_at = now()
        where id = v_row.id;

        insert into public.sale_items (sale_id, inventory_id, name, category, condition,
                                       cost_price, selling_price, qty)
        values (v_sale_id, v_row.id, v_row.name, v_row.category, v_row.condition,
                v_row.cost_price, v_row.selling_price, v_qty);

        v_subtotal := v_subtotal + (v_row.selling_price * v_qty);
    end loop;

    v_total := greatest(v_subtotal - coalesce(p_discount, 0)
                        - case when p_sale_type = 'Swap' then coalesce(p_trade_in_value, 0) else 0 end, 0);

    update public.sales set subtotal = v_subtotal, total = v_total where id = v_sale_id;
    return v_sale_id;
end;
$$;

revoke execute on function public.record_sale(jsonb, text, text, numeric, text, numeric, uuid)
    from public, anon;
grant execute on function public.record_sale(jsonb, text, text, numeric, text, numeric, uuid)
    to authenticated;


-- ---------------------------------------------------------------------
-- 2. Clearing practice transactions
-- ---------------------------------------------------------------------
-- Puts back the stock from sales that were never returned, then removes
-- every sale and sales return. Owner and admin only.

create or replace function public.clear_sales_history()
returns jsonb
language plpgsql
security definer
set search_path = public
as $$
declare
    v_sales   integer;
    v_returns integer;
    v_units   integer;
begin
    if not public.is_admin() then
        raise exception 'Not allowed: only the owner or an admin can clear sales history.';
    end if;

    select count(*) into v_sales from public.sales;
    select count(*) into v_returns from public.returns_log;

    select coalesce(sum(si.qty), 0) into v_units
    from public.sale_items si
    join public.sales s on s.id = si.sale_id
    where not s.returned;

    -- A sale already marked returned had its stock restored at the time.
    update public.inventory i
    set stock = i.stock + x.qty, updated_at = now()
    from (
        select si.inventory_id, sum(si.qty) as qty
        from public.sale_items si
        join public.sales s on s.id = si.sale_id
        where not s.returned and si.inventory_id is not null
        group by si.inventory_id
    ) x
    where i.id = x.inventory_id;

    delete from public.returns_log;
    delete from public.sale_items;
    delete from public.sales;

    return jsonb_build_object('sales', v_sales, 'returns', v_returns, 'units_restored', v_units);
end;
$$;

revoke execute on function public.clear_sales_history() from public, anon;
grant execute on function public.clear_sales_history() to authenticated;

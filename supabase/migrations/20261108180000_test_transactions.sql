-- =====================================================================
-- JB Gadgets Store - the owner's own test transactions
-- =====================================================================
-- Boyd needs to be able to ring a sale through to see what happens -
-- what prints, what the figures do, whether a plan adds up - without
-- Joseph's books filling up with transactions that never happened.
--
-- So a sale can be marked as a test. A test sale:
--
--   - is invisible to everyone but the owner, in the database itself,
--     not merely hidden on screen;
--   - does not touch stock, so nobody else sees a phone disappear off
--     the shelf with no sale to explain it;
--   - can be cleared out on its own, leaving the real books alone.
--
-- Only the owner can mark one. An admin asking for a test sale is
-- refused outright rather than quietly given a real one.
--
-- Clearing the whole sales history also becomes the owner's alone. It
-- wipes every sale in the shop, which is not a thing an admin should be
-- able to do on their own.
-- =====================================================================


-- ---------------------------------------------------------------------
-- 1. The mark
-- ---------------------------------------------------------------------
alter table public.sales
    add column if not exists is_test boolean not null default false;

create index if not exists sales_is_test_idx on public.sales (is_test) where is_test;


-- ---------------------------------------------------------------------
-- 2. Who can see one
-- ---------------------------------------------------------------------
-- The owner sees everything. Everyone else sees only real trade.

drop policy if exists staff_read on public.sales;
create policy staff_read on public.sales
    for select to authenticated
    using (public.is_staff() and (public.is_owner() or not is_test));

drop policy if exists admin_read on public.sale_items;
create policy admin_read on public.sale_items
    for select to authenticated
    using (
        public.is_admin()
        and (public.is_owner() or exists (
            select 1 from public.sales s where s.id = sale_id and not s.is_test
        ))
    );

drop policy if exists staff_read on public.returns_log;
create policy staff_read on public.returns_log
    for select to authenticated
    using (
        public.is_staff()
        and (public.is_owner() or exists (
            select 1 from public.sales s where s.id = sale_id and not s.is_test
        ))
    );

-- The receipt view reads the table directly, so it needs the same rule
-- written into it.
create or replace view public.sale_items_for_receipt as
    select si.id, si.sale_id, si.name, si.category, si.condition,
           si.selling_price, si.qty
    from public.sale_items si
    join public.sales s on s.id = si.sale_id
    where public.is_staff()
      and (public.is_owner() or not s.is_test);

revoke all on public.sale_items_for_receipt from public, anon;
grant select on public.sale_items_for_receipt to authenticated;

-- A plan opened on a test sale is a test plan. Dropped rather than
-- replaced, because the new column sits in the middle of the list and
-- a replace cannot reshape a view.
drop view if exists public.hp_book;
create view public.hp_book as
select x.*,
       greatest(x.expected_to_date - x.paid_to_date, 0) as arrears
from (
    select a.id,
           a.sale_id,
           a.customer_name,
           a.customer_phone,
           a.customer_nrc,
           a.cash_price,
           a.deposit,
           a.weekly_payment,
           a.weeks,
           a.total_payable,
           a.total_payable - a.cash_price                        as credit_charge,
           a.started_on,
           a.started_on + (a.weeks * 7)                          as final_due_on,
           a.status,
           a.note,
           s.is_test,
           w.elapsed                                             as weeks_elapsed,
           coalesce(p.paid, 0)                                   as instalments_paid,
           a.deposit + coalesce(p.paid, 0)                       as paid_to_date,
           a.total_payable - a.deposit - coalesce(p.paid, 0)     as balance,
           a.deposit + (a.weekly_payment * w.elapsed)            as expected_to_date,
           p.last_paid                                           as last_payment_on,
           p.payment_count
    from public.hp_agreements a
    join public.sales s on s.id = a.sale_id
    left join (
        select agreement_id,
               sum(amount)   as paid,
               max(paid_on)  as last_paid,
               count(*)      as payment_count
        from public.hp_payments
        group by agreement_id
    ) p on p.agreement_id = a.id
    cross join lateral (
        select least(greatest(floor((current_date - a.started_on) / 7.0), 0), a.weeks)::int
    ) as w(elapsed)
) x
where public.is_staff()
  and (public.is_owner() or not x.is_test);

revoke all on public.hp_book from public, anon;
grant select on public.hp_book to authenticated;

-- The agreement and payment tables underneath the view too.
drop policy if exists staff_read on public.hp_agreements;
create policy staff_read on public.hp_agreements
    for select to authenticated
    using (
        public.is_staff()
        and (public.is_owner() or exists (
            select 1 from public.sales s where s.id = sale_id and not s.is_test
        ))
    );

drop policy if exists staff_read on public.hp_payments;
create policy staff_read on public.hp_payments
    for select to authenticated
    using (
        public.is_staff()
        and (public.is_owner() or exists (
            select 1 from public.hp_agreements a
            join public.sales s on s.id = a.sale_id
            where a.id = agreement_id and not s.is_test
        ))
    );


-- ---------------------------------------------------------------------
-- 3. Ringing up a test sale
-- ---------------------------------------------------------------------
-- Same as a real one except that stock is left alone, and only the
-- owner may ask for it.

drop function if exists public.record_sale(jsonb, text, text, numeric, text, numeric, uuid);

create or replace function public.record_sale(
    p_items           jsonb,
    p_customer_name   text default null,
    p_sale_type       text default 'Cash',
    p_discount        numeric default 0,
    p_trade_in_device text default null,
    p_trade_in_value  numeric default 0,
    p_client_ref      uuid default null,
    p_is_test         boolean default false
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
    v_test     boolean := coalesce(p_is_test, false);
begin
    if not public.is_staff() then
        raise exception 'Not allowed: you are not signed in as staff.';
    end if;
    if v_test and not public.is_owner() then
        raise exception 'Not allowed: only the owner can record a test transaction.';
    end if;
    if p_items is null or jsonb_array_length(p_items) = 0 then
        raise exception 'A sale needs at least one item.';
    end if;

    if p_client_ref is not null then
        select id into v_sale_id from public.sales where client_ref = p_client_ref;
        if found then
            return v_sale_id;
        end if;
    end if;

    insert into public.sales (customer_name, sale_type, discount,
                              trade_in_device, trade_in_value, sold_by, client_ref, is_test)
    values (nullif(p_customer_name, ''), p_sale_type, coalesce(p_discount, 0),
            nullif(p_trade_in_device, ''), coalesce(p_trade_in_value, 0),
            auth.uid(), p_client_ref, v_test)
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

        -- A test sale never moves stock, so nobody else sees a phone
        -- vanish off the shelf.
        if not v_test then
            if v_row.stock < v_qty then
                raise exception 'Only % left of %, cannot sell %.', v_row.stock, v_row.name, v_qty;
            end if;
            update public.inventory
            set stock = stock - v_qty, updated_at = now()
            where id = v_row.id;
        end if;

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

revoke execute on function public.record_sale(jsonb, text, text, numeric, text, numeric, uuid, boolean) from public, anon;
grant  execute on function public.record_sale(jsonb, text, text, numeric, text, numeric, uuid, boolean) to authenticated;


-- A test plan, the same way.
drop function if exists public.record_hire_purchase(jsonb, text, text, text, numeric, numeric, integer, uuid);

create or replace function public.record_hire_purchase(
    p_items          jsonb,
    p_customer_name  text,
    p_customer_phone text    default null,
    p_customer_nrc   text    default null,
    p_deposit        numeric default null,
    p_weekly         numeric default null,
    p_weeks          integer default 12,
    p_client_ref     uuid    default null,
    p_is_test        boolean default false
)
returns bigint
language plpgsql
security definer
set search_path = public
as $$
declare
    v_sale_id      bigint;
    v_agreement_id bigint;
    v_item         jsonb;
    v_row          public.inventory%rowtype;
    v_qty          integer;
    v_cash         numeric(12,2) := 0;
    v_deposit      numeric(12,2) := 0;
    v_weekly       numeric(12,2) := 0;
    v_test         boolean := coalesce(p_is_test, false);
begin
    if not public.is_staff() then
        raise exception 'Not allowed: you are not signed in as staff.';
    end if;
    if v_test and not public.is_owner() then
        raise exception 'Not allowed: only the owner can record a test transaction.';
    end if;
    if p_items is null or jsonb_array_length(p_items) = 0 then
        raise exception 'A hire purchase needs at least one item.';
    end if;
    if coalesce(btrim(p_customer_name), '') = '' then
        raise exception 'A hire purchase needs the customer''s name.';
    end if;
    if p_weeks is null or p_weeks < 1 or p_weeks > 52 then
        raise exception 'The plan must run between 1 and 52 weeks.';
    end if;

    if p_client_ref is not null then
        select a.id into v_agreement_id
        from public.hp_agreements a
        join public.sales s on s.id = a.sale_id
        where s.client_ref = p_client_ref;
        if found then
            return v_agreement_id;
        end if;
    end if;

    insert into public.sales (customer_name, sale_type, sold_by, client_ref, is_test)
    values (btrim(p_customer_name), 'Hire Purchase', auth.uid(), p_client_ref, v_test)
    returning id into v_sale_id;

    for v_item in select * from jsonb_array_elements(p_items)
    loop
        v_qty := (v_item ->> 'qty')::integer;
        if v_qty is null or v_qty < 1 then
            raise exception 'Every line needs a quantity of at least one.';
        end if;

        select * into v_row from public.inventory
        where id = (v_item ->> 'inventory_id')::uuid
        for update;

        if not found then
            raise exception 'That product is no longer in the catalogue.';
        end if;
        if v_row.first_payment is null or v_row.weekly_payment is null then
            raise exception '% is cash only. Set its first payment and weekly amount to sell it on a plan.', v_row.name;
        end if;

        if not v_test then
            if v_row.stock < v_qty then
                raise exception 'Only % left of %, cannot sell %.', v_row.stock, v_row.name, v_qty;
            end if;
            update public.inventory
            set stock = stock - v_qty, updated_at = now()
            where id = v_row.id;
        end if;

        insert into public.sale_items (sale_id, inventory_id, name, category, condition,
                                       cost_price, selling_price, qty)
        values (v_sale_id, v_row.id, v_row.name, v_row.category, v_row.condition,
                v_row.cost_price, v_row.selling_price, v_qty);

        v_cash    := v_cash    + (v_row.selling_price * v_qty);
        v_deposit := v_deposit + (v_row.first_payment  * v_qty);
        v_weekly  := v_weekly  + (v_row.weekly_payment * v_qty);
    end loop;

    v_deposit := coalesce(p_deposit, v_deposit);
    v_weekly  := coalesce(p_weekly,  v_weekly);

    if v_weekly <= 0 then
        raise exception 'The weekly payment must be more than zero.';
    end if;
    if v_deposit < 0 then
        raise exception 'The first payment cannot be negative.';
    end if;

    update public.sales
    set subtotal = v_cash, total = v_deposit
    where id = v_sale_id;

    insert into public.hp_agreements (
        sale_id, customer_name, customer_phone, customer_nrc,
        cash_price, deposit, weekly_payment, weeks, total_payable, opened_by)
    values (
        v_sale_id, btrim(p_customer_name), nullif(btrim(p_customer_phone), ''),
        nullif(btrim(p_customer_nrc), ''),
        v_cash, v_deposit, v_weekly, p_weeks,
        v_deposit + (v_weekly * p_weeks), auth.uid())
    returning id into v_agreement_id;

    return v_agreement_id;
end;
$$;

revoke execute on function public.record_hire_purchase(jsonb, text, text, text, numeric, numeric, integer, uuid, boolean) from public, anon;
grant  execute on function public.record_hire_purchase(jsonb, text, text, text, numeric, numeric, integer, uuid, boolean) to authenticated;


-- ---------------------------------------------------------------------
-- 4. Clearing up
-- ---------------------------------------------------------------------
-- Test transactions on their own. No stock to put back, because none
-- was ever taken.

create or replace function public.clear_test_transactions()
returns jsonb
language plpgsql
security definer
set search_path = public
as $$
declare
    v_sales integer;
begin
    if not public.is_owner() then
        raise exception 'Not allowed: only the owner can clear test transactions.';
    end if;

    select count(*) into v_sales from public.sales where is_test;

    delete from public.hp_payments p
    using public.hp_agreements a, public.sales s
    where p.agreement_id = a.id and a.sale_id = s.id and s.is_test;

    delete from public.hp_agreements a using public.sales s
    where a.sale_id = s.id and s.is_test;

    delete from public.returns_log r using public.sales s
    where r.sale_id = s.id and s.is_test;

    delete from public.sale_items si using public.sales s
    where si.sale_id = s.id and s.is_test;

    delete from public.sales where is_test;

    return jsonb_build_object('test_sales_removed', v_sales);
end;
$$;

revoke execute on function public.clear_test_transactions() from public, anon;
grant  execute on function public.clear_test_transactions() to authenticated;


-- Wiping the whole history is the owner's alone from here on.
create or replace function public.clear_sales_history()
returns jsonb
language plpgsql
security definer
set search_path = public
as $$
declare
    v_sales      integer;
    v_returns    integer;
    v_agreements integer;
    v_units      integer;
begin
    if not public.is_owner() then
        raise exception 'Not allowed: only the owner can clear the sales history.';
    end if;

    select count(*) into v_sales      from public.sales;
    select count(*) into v_returns    from public.returns_log;
    select count(*) into v_agreements from public.hp_agreements;

    -- Only real sales ever took stock, so only those give it back.
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

    delete from public.hp_payments;
    delete from public.hp_agreements;
    delete from public.returns_log;
    delete from public.sale_items;
    delete from public.sales;

    return jsonb_build_object('sales', v_sales, 'returns', v_returns,
                              'agreements', v_agreements, 'units_restored', v_units);
end;
$$;

revoke execute on function public.clear_sales_history() from public, anon;
grant  execute on function public.clear_sales_history() to authenticated;


-- A test sale is not returned over the counter either; it is cleared.
create or replace function public.process_return(
    p_sale_id bigint,
    p_reason  text default 'Customer Return'
)
returns void
language plpgsql
security definer
set search_path = public
as $$
declare
    v_sale public.sales%rowtype;
    v_item public.sale_items%rowtype;
begin
    if not public.is_staff() then
        raise exception 'Not allowed: you are not signed in as staff.';
    end if;

    select * into v_sale from public.sales where id = p_sale_id for update;
    if not found then
        raise exception 'Sale % was not found.', p_sale_id;
    end if;
    if v_sale.returned then
        raise exception 'Sale % has already been returned.', p_sale_id;
    end if;
    if v_sale.sale_type = 'Hire Purchase' then
        raise exception 'Sale % is a hire purchase. Write the agreement off instead, which keeps the payments already taken on the books.', p_sale_id;
    end if;
    if v_sale.is_test then
        raise exception 'Sale % is a test transaction. Clear test transactions instead.', p_sale_id;
    end if;

    for v_item in select * from public.sale_items where sale_id = p_sale_id
    loop
        if v_item.inventory_id is not null then
            update public.inventory
            set stock = stock + v_item.qty, updated_at = now()
            where id = v_item.inventory_id;
        end if;
    end loop;

    update public.sales set returned = true where id = p_sale_id;

    insert into public.returns_log (sale_id, reason, refund_total, handled_by)
    values (p_sale_id, coalesce(nullif(p_reason, ''), 'Customer Return'), v_sale.total, auth.uid());
end;
$$;

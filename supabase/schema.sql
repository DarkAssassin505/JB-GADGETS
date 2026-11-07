-- =====================================================================
-- JB Gadgets Store - database setup for Supabase
-- =====================================================================
-- Paste this whole file into Supabase: SQL Editor -> New query -> Run.
-- It is safe to run more than once.
--
-- One shop, staff with their own logins, three roles:
--   owner   - everything an admin can do, and invisible to everyone else.
--             No other signed-in user can see that this account exists.
--   admin   - sees cost prices, profit, expenses and settings, and brings
--             new staff on board. Cannot see, change or create an owner.
--   cashier - sells, books repairs, handles customers; no cost or profit
--
-- New sign-ups arrive switched off and see nothing until an owner or an
-- admin switches them on, so a stranger finding the page gains nothing.
--
-- Money is stored as numeric(12,2), which is exact to the ngwee.
-- =====================================================================


-- ---------------------------------------------------------------------
-- 1. Staff
-- ---------------------------------------------------------------------
-- Supabase keeps logins in its own auth.users table. This adds the name
-- and the role on top of it.

create table if not exists public.profiles (
    id         uuid primary key references auth.users (id) on delete cascade,
    full_name  text not null default 'New staff member',
    role       text not null default 'cashier' check (role in ('owner', 'admin', 'cashier')),
    is_active  boolean not null default false,
    created_at timestamptz not null default now()
);

-- If this is an upgrade from the two-role version, widen the rule and
-- make sure nobody is left switched on by accident.
alter table public.profiles drop constraint if exists profiles_role_check;
alter table public.profiles add constraint profiles_role_check
    check (role in ('owner', 'admin', 'cashier'));
alter table public.profiles alter column is_active set default false;

-- There is exactly one owner. Remove this line if you ever want two.
create unique index if not exists profiles_single_owner
    on public.profiles ((role)) where role = 'owner';

-- Anyone who signs up starts as a switched-off cashier, so an account
-- alone grants nothing until somebody approves it.
create or replace function public.handle_new_user()
returns trigger
language plpgsql
security definer
set search_path = public
as $$
begin
    insert into public.profiles (id, full_name)
    values (new.id, coalesce(new.raw_user_meta_data ->> 'full_name', new.email))
    on conflict (id) do nothing;
    return new;
end;
$$;

drop trigger if exists on_auth_user_created on auth.users;
create trigger on_auth_user_created
    after insert on auth.users
    for each row execute function public.handle_new_user();

-- Asking "is the person signed in an admin?" inside a security rule would
-- loop forever if it read the table normally, so it goes through this.
create or replace function public.is_owner()
returns boolean
language sql
security definer
stable
set search_path = public
as $$
    select exists (
        select 1 from public.profiles
        where id = auth.uid() and role = 'owner' and is_active
    );
$$;

-- The owner can do everything an admin can, so every admin rule below
-- covers the owner too.
create or replace function public.is_admin()
returns boolean
language sql
security definer
stable
set search_path = public
as $$
    select exists (
        select 1 from public.profiles
        where id = auth.uid() and role in ('owner', 'admin') and is_active
    );
$$;

create or replace function public.is_staff()
returns boolean
language sql
security definer
stable
set search_path = public
as $$
    select exists (
        select 1 from public.profiles
        where id = auth.uid() and is_active
    );
$$;


-- ---------------------------------------------------------------------
-- 2. The shop's records
-- ---------------------------------------------------------------------

create table if not exists public.inventory (
    id            uuid primary key default gen_random_uuid(),
    name          text not null,
    category      text not null check (category in ('Phones', 'Accessories', 'Consoles')),
    condition     text not null check (condition in ('Brand New', 'Pre-Owned')),
    cost_price    numeric(12,2) not null default 0 check (cost_price >= 0),
    selling_price numeric(12,2) not null check (selling_price >= 0),
    stock         integer not null default 0 check (stock >= 0),
    created_at    timestamptz not null default now(),
    updated_at    timestamptz not null default now()
);

-- The app matches a cart line to stock by name + condition, so that pair
-- must be unique or the wrong row could be reduced.
create unique index if not exists inventory_name_condition_key
    on public.inventory (lower(name), condition);

create table if not exists public.customers (
    id         uuid primary key default gen_random_uuid(),
    name       text not null,
    phone      text not null unique,
    created_at timestamptz not null default now()
);

-- Receipt numbers now run in order instead of being random, so two sales
-- can never end up with the same number.
create table if not exists public.sales (
    id             bigint generated by default as identity (start with 1001) primary key,
    sold_at        timestamptz not null default now(),
    customer_name  text,
    sale_type      text not null default 'Cash' check (sale_type in ('Cash', 'Swap')),
    subtotal       numeric(12,2) not null default 0 check (subtotal >= 0),
    discount       numeric(12,2) not null default 0 check (discount >= 0),
    trade_in_device text,
    trade_in_value numeric(12,2) not null default 0 check (trade_in_value >= 0),
    total          numeric(12,2) not null default 0 check (total >= 0),
    returned       boolean not null default false,
    sold_by        uuid references public.profiles (id),
    created_at     timestamptz not null default now()
);

create table if not exists public.sale_items (
    id            uuid primary key default gen_random_uuid(),
    sale_id       bigint not null references public.sales (id) on delete cascade,
    inventory_id  uuid references public.inventory (id),
    name          text not null,
    category      text not null,
    condition     text not null,
    cost_price    numeric(12,2) not null default 0,
    selling_price numeric(12,2) not null,
    qty           integer not null check (qty > 0)
);
create index if not exists sale_items_sale_idx on public.sale_items (sale_id);

create table if not exists public.returns_log (
    id           uuid primary key default gen_random_uuid(),
    sale_id      bigint not null references public.sales (id),
    return_date  timestamptz not null default now(),
    reason       text not null default 'Customer Return',
    refund_total numeric(12,2) not null default 0,
    handled_by   uuid references public.profiles (id)
);

create table if not exists public.repairs (
    id         uuid primary key default gen_random_uuid(),
    customer   text not null,
    phone      text not null,
    device     text not null,
    issue      text not null,
    status     text not null default 'Pending'
               check (status in ('Pending', 'In Progress', 'Ready', 'Collected')),
    created_at timestamptz not null default now(),
    updated_at timestamptz not null default now()
);

create table if not exists public.expenses (
    id          uuid primary key default gen_random_uuid(),
    spent_on    date not null default current_date,
    description text not null,
    amount      numeric(12,2) not null check (amount >= 0),
    created_by  uuid references public.profiles (id),
    created_at  timestamptz not null default now()
);

-- One row, holding the store name, location, currency and receipt footer.
create table if not exists public.settings (
    id             boolean primary key default true check (id),
    store_name     text not null default 'JB GADGETS STORE',
    location       text not null default 'Lusaka, Zambia',
    currency       text not null default 'ZMW',
    receipt_footer text not null default 'Thank you for your business!',
    updated_at     timestamptz not null default now()
);
insert into public.settings (id) values (true) on conflict (id) do nothing;


-- ---------------------------------------------------------------------
-- 3. Selling and returning, done by the database
-- ---------------------------------------------------------------------
-- Stock changes go through these two steps rather than the page editing
-- stock directly. That means two tills can never sell the same last unit,
-- and a cashier never needs permission to change stock by hand.

create or replace function public.record_sale(
    p_items         jsonb,              -- [{"inventory_id":"...","qty":2}, ...]
    p_customer_name text default null,
    p_sale_type     text default 'Cash',
    p_discount      numeric default 0,
    p_trade_in_device text default null,
    p_trade_in_value  numeric default 0
)
returns bigint
language plpgsql
security definer
set search_path = public
as $$
declare
    v_sale_id   bigint;
    v_item      jsonb;
    v_row       public.inventory%rowtype;
    v_qty       integer;
    v_subtotal  numeric(12,2) := 0;
    v_total     numeric(12,2);
begin
    if not public.is_staff() then
        raise exception 'Not allowed: you are not signed in as staff.';
    end if;
    if p_items is null or jsonb_array_length(p_items) = 0 then
        raise exception 'A sale needs at least one item.';
    end if;

    insert into public.sales (customer_name, sale_type, discount,
                              trade_in_device, trade_in_value, sold_by)
    values (nullif(p_customer_name, ''), p_sale_type, coalesce(p_discount, 0),
            nullif(p_trade_in_device, ''), coalesce(p_trade_in_value, 0), auth.uid())
    returning id into v_sale_id;

    for v_item in select * from jsonb_array_elements(p_items)
    loop
        v_qty := (v_item ->> 'qty')::integer;

        -- lock the row so a second till cannot take the same unit
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


-- ---------------------------------------------------------------------
-- 4. What a cashier is allowed to see
-- ---------------------------------------------------------------------
-- Cashiers read the catalogue through this list, which simply has no cost
-- price in it. Hiding the figure on screen alone would not be enough -
-- anyone could still read it out of the connection.

-- A view runs with its owner's permissions, so these two reach the tables
-- that cashiers themselves cannot open. That also means the row rules do
-- NOT apply to them, so each one has to check for itself that the caller
-- is active staff. Without that line, anyone who merely holds a login
-- could read the catalogue.

create or replace view public.inventory_for_sale as
    select id, name, category, condition, selling_price, stock
    from public.inventory
    where public.is_staff();

create or replace view public.sale_items_for_receipt as
    select id, sale_id, name, category, condition, selling_price, qty
    from public.sale_items
    where public.is_staff();

revoke all on public.inventory_for_sale from anon, authenticated;
revoke all on public.sale_items_for_receipt from anon, authenticated;
grant select on public.inventory_for_sale to authenticated;
grant select on public.sale_items_for_receipt to authenticated;


-- ---------------------------------------------------------------------
-- 5. Access rules
-- ---------------------------------------------------------------------
-- Nothing here is readable by the public. Every rule below requires a
-- signed-in member of staff, and the admin-only rules require the admin
-- role on top of that.

alter table public.profiles    enable row level security;
alter table public.inventory   enable row level security;
alter table public.customers   enable row level security;
alter table public.sales       enable row level security;
alter table public.sale_items  enable row level security;
alter table public.returns_log enable row level security;
alter table public.repairs     enable row level security;
alter table public.expenses    enable row level security;
alter table public.settings    enable row level security;

do $$
declare t text;
begin
    foreach t in array array['profiles','inventory','customers','sales','sale_items',
                             'returns_log','repairs','expenses','settings']
    loop
        execute format('drop policy if exists staff_read on public.%I', t);
        execute format('drop policy if exists staff_write on public.%I', t);
        execute format('drop policy if exists admin_read on public.%I', t);
        execute format('drop policy if exists admin_all on public.%I', t);
    end loop;
end;
$$;

-- The staff list. Everyone sees their own row, even before being
-- switched on, so the app can tell them they are waiting for approval.
-- Staff see each other, but the owner's row is filtered out for them:
-- to everyone except the owner, that account does not appear to exist.
create policy staff_read on public.profiles
    for select to authenticated
    using (
        id = auth.uid()
        or public.is_owner()
        or (public.is_staff() and role <> 'owner')
    );

-- Admins bring staff on board and set their role, but cannot touch the
-- owner's row and cannot make anyone an owner, themselves included.
create policy admin_all on public.profiles
    for all to authenticated
    using      (public.is_owner() or (public.is_admin() and role <> 'owner'))
    with check (public.is_owner() or (public.is_admin() and role <> 'owner'));

-- Cost prices: admin only. Cashiers use inventory_for_sale instead.
create policy admin_all on public.inventory
    for all to authenticated using (public.is_admin()) with check (public.is_admin());

-- Takings: any signed-in staff member may read and record them.
create policy staff_read on public.sales
    for select to authenticated using (public.is_staff());
-- sale_items carries the cost price of each line, so only an admin reads it
-- directly; everyone else gets sale_items_for_receipt.
create policy admin_read on public.sale_items
    for select to authenticated using (public.is_admin());
create policy staff_read on public.returns_log
    for select to authenticated using (public.is_staff());

create policy staff_write on public.customers
    for all to authenticated using (public.is_staff()) with check (public.is_staff());
create policy staff_write on public.repairs
    for all to authenticated using (public.is_staff()) with check (public.is_staff());

-- Expenses and shop settings: admin only.
create policy admin_all on public.expenses
    for all to authenticated using (public.is_admin()) with check (public.is_admin());
create policy staff_read on public.settings
    for select to authenticated using (public.is_staff());
create policy admin_all on public.settings
    for all to authenticated using (public.is_admin()) with check (public.is_admin());

-- Sales and stock are only ever changed through the two steps in part 3.
revoke insert, update, delete on public.sales, public.sale_items, public.returns_log
    from anon, authenticated;
-- These two run with raised permissions, so take them away from everyone
-- first and hand them back only to signed-in staff.
revoke execute on function public.record_sale(jsonb, text, text, numeric, text, numeric)
    from public, anon;
revoke execute on function public.process_return(bigint, text) from public, anon;
grant execute on function public.record_sale(jsonb, text, text, numeric, text, numeric) to authenticated;
grant execute on function public.process_return(bigint, text) to authenticated;


-- ---------------------------------------------------------------------
-- 6. Starting stock
-- ---------------------------------------------------------------------
-- The four products the app shipped with. Delete or edit them later in
-- the Inventory tab; prices are in kwacha.

insert into public.inventory (name, category, condition, cost_price, selling_price, stock)
values
    ('iPhone 15 Pro',  'Phones',      'Brand New', 18000, 22000, 5),
    ('iPhone 13 128GB','Phones',      'Pre-Owned',  9000, 11500, 3),
    ('AirPods Pro 2',  'Accessories', 'Brand New',  3500,  4500, 4),
    ('PlayStation 5',  'Consoles',    'Brand New', 10000, 12500, 2)
on conflict do nothing;


-- =====================================================================
-- AFTER RUNNING THIS
--
-- Add the logins under Authentication -> Users first, then run the two
-- lines below on their own, with the real email addresses in them.
-- Every new account starts switched off, so this also switches them on.
--
-- 1. Make yourself the owner:
--
--   update public.profiles
--   set role = 'owner', full_name = 'Boyd Longwe', is_active = true
--   where id = (select id from auth.users where email = 'you@example.com');
--
-- 2. Make Joseph an admin, so he can bring the rest of the staff on:
--
--   update public.profiles
--   set role = 'admin', full_name = 'Joseph', is_active = true
--   where id = (select id from auth.users where email = 'joseph@example.com');
--
-- Each should answer UPDATE 1. UPDATE 0 means the email does not match
-- a login you created.
--
-- NOTE: this hides the owner from everyone inside the app. It cannot
-- hide anything from someone you invite into the Supabase dashboard
-- itself, because the dashboard works beneath these rules. Keep the
-- dashboard to yourself.
-- =====================================================================

-- =====================================================================
-- JB Gadgets Store - a QR code on the receipt, and who sets the
-- discount limit
-- =====================================================================
-- Two changes.
--
--   1. The receipt can carry a QR code. What it points at is part of
--      the receipt's design, so it belongs to the owner along with
--      everything else that prints.
--
--   2. The largest discount anyone may give moves from the owner's
--      rules to the shop settings, so Joseph sets it. It is a trading
--      decision for whoever runs the shop, not a platform one.
-- =====================================================================


-- ---------------------------------------------------------------------
-- 1. The QR code
-- ---------------------------------------------------------------------
alter table public.receipt_design
    add column if not exists qr_mode     text not null default 'off',
    add column if not exists qr_link     text not null default '',
    add column if not exists qr_whatsapp text not null default '',
    add column if not exists qr_label    text not null default 'Scan to contact us';

alter table public.receipt_design drop constraint if exists receipt_design_qr_mode_check;
alter table public.receipt_design add constraint receipt_design_qr_mode_check
    check (qr_mode in ('off', 'link', 'whatsapp', 'receipt'));

comment on column public.receipt_design.qr_mode is
    'off: no code. link: the address in qr_link. whatsapp: a chat with '
    'qr_whatsapp, with the receipt number already typed. receipt: the '
    'sale written out, so it reads with no internet at all.';


-- ---------------------------------------------------------------------
-- 2. The discount limit becomes the shop's, not the platform's
-- ---------------------------------------------------------------------
alter table public.settings
    add column if not exists max_discount_percent numeric(5,2);

-- Carry across whatever the owner had set, the first time this runs.
do $$
begin
    if exists (select 1 from information_schema.columns
               where table_schema = 'public' and table_name = 'owner_settings'
                 and column_name = 'max_discount_percent') then
        execute $q$
            update public.settings s
            set max_discount_percent = coalesce(s.max_discount_percent, o.max_discount_percent)
            from public.owner_settings o
            where o.id
        $q$;
    end if;
end
$$;

update public.settings set max_discount_percent = 10 where max_discount_percent is null;

alter table public.settings alter column max_discount_percent set not null;
alter table public.settings alter column max_discount_percent set default 10;

alter table public.settings drop constraint if exists settings_max_discount_check;
alter table public.settings add constraint settings_max_discount_check
    check (max_discount_percent between 0 and 100);

-- And off the owner's rules, so there is only ever one of it.
alter table public.owner_settings drop column if exists max_discount_percent;

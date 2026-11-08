-- =====================================================================
-- JB Gadgets Store - the activity log becomes the owner's alone
-- =====================================================================
-- It was readable by the owner and the shop admin, with the owner's own
-- entries hidden from the admin. The shop would rather not hold it at
-- all and ask for it when it is wanted, so it is now the owner's only.
--
-- Nothing about how it is written changes: every price change, hand-made
-- stock move, write-off, staff change and settings edit is still
-- recorded, by the database, and still cannot be edited or deleted by
-- anyone. Only who may read it changes.
-- =====================================================================

drop policy if exists admin_read on public.audit_log;
drop policy if exists owner_read on public.audit_log;

create policy owner_read on public.audit_log
    for select to authenticated using (public.is_owner());

-- Unchanged, and worth restating: nobody writes to it directly.
revoke insert, update, delete on public.audit_log from anon, authenticated;

// =====================================================================
// set-staff-password
// =====================================================================
// A cashier has no email address, so there is nowhere to send a reset
// link. This lets the owner or an admin set a new password directly.
//
// Changing somebody else's password needs the service role key, which
// must never sit in the app where a customer could read it. So it lives
// here instead, on the server, behind these checks:
//
//   - the caller must be signed in, active, and an owner or an admin
//   - an admin may set a password for a cashier or another admin
//   - only the owner may set the owner's password, and the owner's
//     account is invisible to an admin in the first place
//
// That last rule is the important one. Without it an admin could set a
// new password on the owner's account and then sign in as the owner.
// =====================================================================

import { createClient } from 'https://esm.sh/@supabase/supabase-js@2.45.4';

const cors = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Headers': 'authorization, x-client-info, apikey, content-type',
  'Access-Control-Allow-Methods': 'POST, OPTIONS',
};

const reply = (body: unknown, status = 200) =>
  new Response(JSON.stringify(body), {
    status,
    headers: { ...cors, 'Content-Type': 'application/json' },
  });

Deno.serve(async (req) => {
  if (req.method === 'OPTIONS') return new Response('ok', { headers: cors });
  if (req.method !== 'POST') return reply({ error: 'Use POST.' }, 405);

  const url     = Deno.env.get('SUPABASE_URL')!;
  const anonKey = Deno.env.get('SUPABASE_ANON_KEY')!;
  const svcKey  = Deno.env.get('SUPABASE_SERVICE_ROLE_KEY')!;

  const authHeader = req.headers.get('Authorization') ?? '';
  if (!authHeader.startsWith('Bearer ')) {
    return reply({ error: 'Not signed in.' }, 401);
  }

  // Who is asking? Read it from their token, never from the request body.
  const asCaller = createClient(url, anonKey, {
    global: { headers: { Authorization: authHeader } },
  });
  const { data: who, error: whoErr } = await asCaller.auth.getUser();
  if (whoErr || !who?.user) return reply({ error: 'Not signed in.' }, 401);

  const admin = createClient(url, svcKey, { auth: { persistSession: false } });

  const { data: caller } = await admin
    .from('profiles').select('role, is_active').eq('id', who.user.id).maybeSingle();

  if (!caller || !caller.is_active || !['owner', 'admin'].includes(caller.role)) {
    return reply({ error: 'Only the owner or an admin can set a password.' }, 403);
  }

  let body: { user_id?: string; password?: string };
  try {
    body = await req.json();
  } catch {
    return reply({ error: 'Could not read the request.' }, 400);
  }

  const targetId = (body.user_id ?? '').trim();
  const password = body.password ?? '';

  if (!targetId) return reply({ error: 'Which account?' }, 400);
  if (password.length < 8) {
    return reply({ error: 'A password needs at least 8 characters.' }, 400);
  }

  const { data: target } = await admin
    .from('profiles').select('role, full_name').eq('id', targetId).maybeSingle();

  if (!target) return reply({ error: 'That account does not exist.' }, 404);

  // An admin cannot touch the owner, by any route.
  if (target.role === 'owner' && caller.role !== 'owner') {
    return reply({ error: 'That account does not exist.' }, 404);
  }

  const { error: setErr } = await admin.auth.admin.updateUserById(targetId, { password });
  if (setErr) return reply({ error: setErr.message }, 400);

  return reply({ ok: true, full_name: target.full_name });
});

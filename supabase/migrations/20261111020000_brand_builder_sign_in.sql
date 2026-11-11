-- 34 Brand Builder: username + password sign-in for the client area.
-- Additive only: three new tables and one helper function. Nothing existing is changed or dropped.
-- Same lock-down as the existing tables: RLS on with no policies, no grants to anon/authenticated,
-- so only the brand-builder edge function (service role) can read or write them.

-- One sign-in per client link. Passwords are never stored: only a PBKDF2-SHA-256 hash with a per-user salt.
create table public.logins (
  link_id uuid primary key references public.links(id) on delete cascade,
  username text not null unique
    check (username = lower(username) and username ~ '^[a-z0-9][a-z0-9._@-]{2,63}$'),
  pw_algo text not null default 'pbkdf2-sha256',
  pw_iter int not null check (pw_iter >= 210000),
  pw_salt text not null,
  pw_hash text not null,
  set_at timestamptz not null default now(),
  last_login_at timestamptz,
  login_count int not null default 0
);
alter table public.logins enable row level security;
revoke all on public.logins from anon, authenticated;

-- Sign-in sessions: a fresh random token per sign-in; only its SHA-256 fingerprint is kept.
create table public.sessions (
  id uuid primary key default gen_random_uuid(),
  token_hash text not null unique,
  link_id uuid not null references public.links(id) on delete cascade,
  created_at timestamptz not null default now(),
  expires_at timestamptz not null,
  revoked boolean not null default false,
  device_id text,
  last_seen_at timestamptz
);
create index sessions_link_idx on public.sessions (link_id);
create index sessions_expires_idx on public.sessions (expires_at);
alter table public.sessions enable row level security;
revoke all on public.sessions from anon, authenticated;

-- Failed sign-in counters. key = 'u:' or 'ip:' + keyed hash, so no usernames or IP addresses are stored.
create table public.login_attempts (
  key text primary key,
  fails int not null default 0,
  window_start timestamptz not null default now(),
  locked_until timestamptz,
  updated_at timestamptz not null default now()
);
alter table public.login_attempts enable row level security;
revoke all on public.login_attempts from anon, authenticated;

-- Atomically record one failed attempt against each key. 5 failures inside 15 minutes locks that key
-- for 15 minutes. Returns the latest lock end among the keys, or null if none is locked.
create function public.bb_login_fail(p_keys text[])
returns timestamptz
language plpgsql
security invoker
set search_path = ''
as $$
declare
  v_until timestamptz;
begin
  insert into public.login_attempts as a (key, fails, window_start, locked_until, updated_at)
  select distinct k, 1, now(), null::timestamptz, now() from unnest(p_keys) as k
  on conflict (key) do update set
    fails = case when a.window_start < now() - interval '15 minutes' or a.locked_until <= now()
                 then 1 else a.fails + 1 end,
    window_start = case when a.window_start < now() - interval '15 minutes' or a.locked_until <= now()
                 then now() else a.window_start end,
    locked_until = case
                 when (case when a.window_start < now() - interval '15 minutes' or a.locked_until <= now()
                            then 1 else a.fails + 1 end) >= 5 then now() + interval '15 minutes'
                 when a.window_start < now() - interval '15 minutes' or a.locked_until <= now() then null
                 else a.locked_until end,
    updated_at = now();
  select max(locked_until) into v_until
    from public.login_attempts where key = any (p_keys) and locked_until > now();
  return v_until;
end;
$$;
revoke all on function public.bb_login_fail(text[]) from public, anon, authenticated;
grant execute on function public.bb_login_fail(text[]) to service_role;

-- let the API layer see the new tables straight away
notify pgrst, 'reload schema';

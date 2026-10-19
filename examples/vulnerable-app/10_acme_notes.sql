-- "Acme Notes": a small multi-tenant SaaS schema with deliberate security holes.
--
-- Every object is tagged:
--   VULN <check> (<severity>)  se-check must report it; probe-* checks with `audit --probe`
--   SAFE                       se-check must stay quiet, with and without --probe
--
-- tests/test_integration.py asserts exactly this list of findings (EXPECTED, EXPECTED_PROBE).

-- ---------------------------------------------------------------------------------------------
-- Tenancy core. SAFE.
-- ---------------------------------------------------------------------------------------------

-- Helpers and reference data live in a schema the API does not expose.
create schema private;
grant usage on schema private to authenticated;

-- SAFE: reference data whose codes a CHECK constrains, so the probe can't make up a row of its
-- own. A tenant may have no tier: the probe leaves it NULL. Every project has a status: the
-- probe takes one the table already holds, without reading it.
create table private.tiers (
  code text primary key check (code ~ '^[a-z]+$')
);
create table private.project_statuses (
  code text primary key check (code ~ '^[a-z]+$')
);
insert into private.project_statuses (code) values ('active'), ('archived');

create table public.tenants (
  id uuid primary key default gen_random_uuid(),
  name text not null,
  tier text references private.tiers (code)
);

create table public.memberships (
  user_id uuid not null references auth.users (id),
  tenant_id uuid not null references public.tenants (id),
  role text not null default 'member',
  primary key (user_id, tenant_id)
);

-- SAFE: SECURITY DEFINER to avoid RLS recursion, fixed search_path, not exposed.
create function private.my_tenant_ids() returns setof uuid
language sql stable security definer set search_path = ''
as $$
  select tenant_id from public.memberships where user_id = auth.uid()
$$;

-- SAFE: the project's permission guard.
create function private.has_permission(p_tenant uuid, p_permission text) returns boolean
language sql stable security definer set search_path = ''
as $$
  select exists (
    select 1 from public.memberships m
    where m.user_id = auth.uid()
      and m.tenant_id = p_tenant
      and (m.role = 'admin' or p_permission = 'read')
  )
$$;

alter table public.tenants enable row level security;
create policy "members read their tenants" on public.tenants
  for select to authenticated
  using (id in (select private.my_tenant_ids()));

alter table public.memberships enable row level security;
create policy "users read their memberships" on public.memberships
  for select to authenticated
  using (user_id = auth.uid());

-- ---------------------------------------------------------------------------------------------
-- SAFE: proper tenant isolation.
-- ---------------------------------------------------------------------------------------------

create table public.projects (
  id uuid primary key default gen_random_uuid(),
  tenant_id uuid not null references public.tenants (id),
  name text not null,
  status text not null references private.project_statuses (code)
);
alter table public.projects enable row level security;
create policy "members read projects" on public.projects
  for select to authenticated
  using (tenant_id in (select private.my_tenant_ids()));
create policy "admins write projects" on public.projects
  for all to authenticated
  using (private.has_permission(tenant_id, 'write'))
  with check (private.has_permission(tenant_id, 'write'));

-- ---------------------------------------------------------------------------------------------
-- rls-disabled
-- ---------------------------------------------------------------------------------------------

-- VULN rls-disabled (critical), probe-anon-access (critical): anyone with the anon key reads and
-- writes every tenant's invoices.
create table public.invoices (
  id uuid primary key default gen_random_uuid(),
  tenant_id uuid not null references public.tenants (id),
  amount_cents integer not null
);

-- VULN rls-disabled (low): no API grants today, but nothing stops the next GRANT.
create table public.audit_log (
  id bigint generated always as identity primary key,
  tenant_id uuid,
  event text not null
);
revoke all on public.audit_log from anon, authenticated;

-- ---------------------------------------------------------------------------------------------
-- permissive-policy
-- ---------------------------------------------------------------------------------------------

-- VULN permissive-policy (high), probe-cross-tenant-read (high): tenant-scoped, readable by
-- every logged-in user.
create table public.documents (
  id uuid primary key default gen_random_uuid(),
  tenant_id uuid not null references public.tenants (id),
  title text not null,
  body text
);
alter table public.documents enable row level security;
create policy "logged in users read documents" on public.documents
  for select to authenticated
  using (true);
-- SAFE: this one is scoped correctly.
create policy "members add documents" on public.documents
  for insert to authenticated
  with check (tenant_id in (select private.my_tenant_ids()));

-- VULN permissive-policy (high), probe-cross-tenant-read (high), probe-cross-tenant-write (high):
-- "is logged in" is not authorization.
create table public.tasks (
  id uuid primary key default gen_random_uuid(),
  tenant_id uuid not null references public.tenants (id),
  title text not null,
  done boolean not null default false
);
alter table public.tasks enable row level security;
create policy "authenticated users manage tasks" on public.tasks
  for all to authenticated
  using ((select auth.uid()) is not null);

-- VULN permissive-policy (low), probe-anon-access (low): public reference data, flagged so you
-- can confirm it's meant.
create table public.plans (
  id text primary key,
  name text not null,
  price_cents integer not null
);
alter table public.plans enable row level security;
create policy "plans are public" on public.plans
  for select to anon, authenticated
  using (true);

-- VULN permissive-policy (medium), probe-anon-access (medium): anonymous inserts. Fine for a
-- contact form, if intended.
create table public.feedback (
  id bigint generated always as identity primary key,
  message text not null,
  created_at timestamptz not null default now()
);
alter table public.feedback enable row level security;
create policy "anyone can send feedback" on public.feedback
  for insert to anon
  with check (true);

-- ---------------------------------------------------------------------------------------------
-- user-metadata-auth
-- ---------------------------------------------------------------------------------------------

-- VULN user-metadata-auth (high), probe-cross-tenant-read (high): the tenant comes from metadata
-- the user can edit; the probe's mallory writes tenant B there and reads tenant B's profiles.
create table public.profiles (
  id uuid primary key references auth.users (id),
  tenant_id uuid references public.tenants (id),
  full_name text,
  role text not null default 'member'
);
alter table public.profiles enable row level security;
create policy "read profiles of my tenant" on public.profiles
  for select to authenticated
  using (tenant_id = ((auth.jwt() -> 'user_metadata') ->> 'tenant_id')::uuid);
-- VULN probe-self-escalation (high): users can set their own `role` to 'admin'. Statically this
-- policy looks fine.
create policy "users update their profile" on public.profiles
  for update to authenticated
  using (id = auth.uid());

-- VULN user-metadata-auth (high): same mistake, hidden in a helper function.
create function private.tenant_from_metadata() returns uuid
language sql stable security definer set search_path = ''
as $$
  select (raw_user_meta_data ->> 'tenant_id')::uuid from auth.users where id = auth.uid()
$$;

-- VULN probe-cross-tenant-read (high): through that helper, mallory reads tenant B's comments.
create table public.comments (
  id uuid primary key default gen_random_uuid(),
  tenant_id uuid not null references public.tenants (id),
  body text not null
);
alter table public.comments enable row level security;
create policy "read comments of my tenant" on public.comments
  for select to authenticated
  using (tenant_id = private.tenant_from_metadata());

-- ---------------------------------------------------------------------------------------------
-- definer-no-caller-check, definer-search-path
-- ---------------------------------------------------------------------------------------------

-- VULN definer-no-caller-check (high) + definer-search-path (medium):
-- anyone can call /rest/v1/rpc/delete_tenant and wipe any tenant.
create function public.delete_tenant(p_tenant uuid) returns void
language plpgsql security definer
as $$
begin
  delete from public.projects where tenant_id = p_tenant;
  delete from public.tenants where id = p_tenant;
end
$$;

-- SAFE: checks the caller first, through private.has_permission(), which reads auth.uid().
create function public.rename_project(p_project uuid, p_name text) returns void
language plpgsql security definer set search_path = ''
as $$
begin
  if not private.has_permission(
    (select tenant_id from public.projects where id = p_project), 'write'
  ) then
    raise exception 'forbidden';
  end if;
  update public.projects set name = p_name where id = p_project;
end
$$;

-- SAFE: filters on the caller's identity itself.
create function public.my_projects() returns setof public.projects
language sql stable security definer set search_path = ''
as $$
  select p.*
  from public.projects p
  join public.memberships m on m.tenant_id = p.tenant_id
  where m.user_id = auth.uid()
$$;

-- SAFE: trigger functions cannot be called through the API, and full_name is harmless metadata.
create function public.handle_new_user() returns trigger
language plpgsql security definer set search_path = ''
as $$
begin
  insert into public.profiles (id, full_name) values (new.id, new.raw_user_meta_data ->> 'full_name');
  return new;
end
$$;
create trigger on_auth_user_created
  after insert on auth.users
  for each row execute function public.handle_new_user();

-- SAFE: the API roles cannot call it.
create function public.refresh_stats() returns void
language plpgsql security definer set search_path = ''
as $$
begin
  perform 1;
end
$$;
revoke execute on function public.refresh_stats() from public, anon, authenticated;

-- VULN definer-search-path (low): not reachable from the API, search_path still not fixed.
create function private.purge_old_audit_log() returns void
language sql security definer
as $$
  delete from public.audit_log where event = 'debug'
$$;

-- ---------------------------------------------------------------------------------------------
-- auth-hook-exposed, signup-trigger-metadata
-- ---------------------------------------------------------------------------------------------

-- VULN auth-hook-exposed (high): Auth needs it, but nobody revoked it from the API roles, so
-- anyone can call /rest/v1/rpc/custom_access_token_hook with any user id and read its claims.
create function public.custom_access_token_hook(event jsonb) returns jsonb
language plpgsql stable security definer set search_path = ''
as $$
declare
  claims jsonb := coalesce(event -> 'claims', '{}');
begin
  claims := jsonb_set(claims, '{tenant_ids}', coalesce((
    select jsonb_agg(m.tenant_id)
    from public.memberships m
    where m.user_id = (event ->> 'user_id')::uuid
  ), '[]'));
  return jsonb_set(event, '{claims}', claims);
end
$$;
grant execute on function public.custom_access_token_hook(jsonb) to supabase_auth_admin;

-- SAFE: the same kind of hook, done right.
create function public.before_user_created_hook(event jsonb) returns jsonb
language plpgsql stable security definer set search_path = ''
as $$
begin
  return '{}'::jsonb;
end
$$;
grant execute on function public.before_user_created_hook(jsonb) to supabase_auth_admin;
revoke execute on function public.before_user_created_hook(jsonb) from public, anon, authenticated;

-- VULN signup-trigger-metadata (high): "invite links" pass the tenant and role in the signup
-- metadata, which the user controls: anyone can sign up as admin of any tenant.
create function public.join_tenant_on_signup() returns trigger
language plpgsql security definer set search_path = ''
as $$
begin
  if new.raw_user_meta_data ? 'tenant_id' then
    insert into public.memberships (user_id, tenant_id, role)
    values (
      new.id,
      (new.raw_user_meta_data ->> 'tenant_id')::uuid,
      coalesce(new.raw_user_meta_data ->> 'role', 'member')
    );
  end if;
  return new;
end
$$;
create trigger on_auth_user_created_join_tenant
  after insert on auth.users
  for each row execute function public.join_tenant_on_signup();

-- ---------------------------------------------------------------------------------------------
-- Rows owned by a user rather than a tenant
-- ---------------------------------------------------------------------------------------------

-- SAFE: private notes; each user reads and writes their own.
create table public.notes (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references auth.users (id),
  body text not null
);
alter table public.notes enable row level security;
create policy "users manage their notes" on public.notes
  for all to authenticated
  using (user_id = (select auth.uid()))
  with check (user_id = (select auth.uid()));

-- VULN permissive-policy (low), probe-cross-user-read (high): direct messages any logged-in user
-- can read. Statically they look like public reference data; the probe sees whose rows they are.
create table public.messages (
  id uuid primary key default gen_random_uuid(),
  recipient_id uuid not null references auth.users (id),
  body text not null
);
alter table public.messages enable row level security;
create policy "logged in users read messages" on public.messages
  for select to authenticated
  using ((select auth.uid()) is not null);

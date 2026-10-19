# Acme Notes: a deliberately vulnerable app

A small multi-tenant SaaS schema with security holes put there on purpose. Use it to see what
se-check reports. It also keeps se-check honest: the test suite asserts that se-check reports
every `VULN` object and stays quiet on every `SAFE` one, with and without the probe.

**Do not reuse this schema.** Half of it is wrong on purpose.

## Run it

With Docker, from the repository root:

```bash
docker compose up -d
se-check audit --dsn postgresql://postgres:postgres@localhost:54329/postgres
se-check audit --dsn postgresql://postgres:postgres@localhost:54329/postgres --probe
docker compose down
```

Without Docker, `uv run python scripts/playground.py` starts a throwaway Postgres loaded with
the same files and opens a menu that runs se-check on it.

On any Postgres, load both files in order into a fresh database, as a superuser: the stub
creates roles.

```bash
psql "$DSN" -f 00_supabase_stub.sql -f 10_acme_notes.sql
```

## Files

| File | |
|---|---|
| `00_supabase_stub.sql` | A minimal stand-in for the parts of Supabase se-check looks at: the API roles, `auth.users`, `auth.uid()`, `auth.role()`, `auth.jwt()` and the default grants on `public`. It is not a full Supabase; it lets the example run on plain Postgres. |
| `10_acme_notes.sql` | The app. Every object is tagged in a comment: `VULN <check> (<severity>)` when se-check must report it (`probe-*` checks only with `--probe`), `SAFE` when it must stay quiet. |

The findings the tests expect are listed in `tests/test_integration.py` (`EXPECTED` and
`EXPECTED_PROBE`). When the SQL and this page disagree, the SQL is right.

## What's inside

| Objects | Tag | Shows |
|---|---|---|
| `tenants`, `memberships`, `projects`, `private.my_tenant_ids()`, `private.has_permission()` | SAFE | Isolation done right: rows tied to the caller's memberships |
| `private.tiers`, `private.project_statuses` | SAFE | Reference data the probe can't make rows of: it leaves `tenants.tier` NULL and gives projects an existing status |
| `invoices` | VULN | RLS disabled on a table the API can reach |
| `audit_log` | VULN | RLS disabled, no grants today |
| `documents` | VULN | `using (true)`: every logged-in user reads every tenant |
| `tasks` | VULN | `auth.uid() is not null`: logged in is not authorization |
| `plans` | VULN | Public reference data, flagged low so you confirm it's meant |
| `feedback` | VULN | Anonymous inserts, fine for a contact form if intended |
| `profiles` | VULN | Tenant taken from `user_metadata`; users can set their own `role` (only the probe sees it) |
| `comments`, `private.tenant_from_metadata()` | VULN | The same `user_metadata` mistake, hidden in a helper |
| `notes` | SAFE | Rows each user reads and writes alone |
| `messages` | VULN | Direct messages any logged-in user reads |
| `delete_tenant()` | VULN | `SECURITY DEFINER`, callable by anyone, no caller check, no fixed `search_path` |
| `rename_project()`, `my_projects()` | SAFE | `SECURITY DEFINER` functions that check the caller |
| `refresh_stats()`, `handle_new_user()` | SAFE | Not callable through the API; a signup trigger that copies a harmless field |
| `private.purge_old_audit_log()` | VULN | `SECURITY DEFINER` without a fixed `search_path`, out of the API's reach |
| `custom_access_token_hook()` | VULN | An Auth hook anyone can also call through `/rpc` |
| `before_user_created_hook()` | SAFE | The same kind of hook, revoked from the API roles |
| `join_tenant_on_signup()` | VULN | A signup trigger that takes the tenant and role from `user_metadata` |

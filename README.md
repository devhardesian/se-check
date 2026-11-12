# se-check

**Find the holes in your Supabase Row Level Security before someone else does.**

se-check audits a Supabase (or any Postgres) database for the authorization mistakes that leak
data between users and tenants: tables without RLS, policies that let every row through,
authorization based on metadata users can edit, `SECURITY DEFINER` functions anyone can call.

- **Static checks** read your tables, grants, policies and functions, explain each hole in
  plain words and suggest a fix you can paste.
- **A dynamic probe** (`--probe`) tries the policies for real: it acts as `anon` and as users
  of two tenants on synthetic rows, inside a transaction it always rolls back.
- **Where you work:** a CLI for your terminal, a GitHub Action that annotates your pull
  requests, and an MCP server, so your AI coding agent can audit the migrations it just wrote
  before telling you it's done.

It reads metadata, never the contents of your tables.

> **Status: alpha (0.1.0).** Not on PyPI yet: install it from source, as shown in
> [Quick start](#quick-start).

## Contents

- [Why](#why)
- [What it looks like](#what-it-looks-like)
- [Quick start](#quick-start)
- [Static checks](#static-checks)
- [Dynamic probe](#dynamic-probe)
- [Use it from your AI agent (MCP)](#use-it-from-your-ai-agent-mcp)
- [In CI (GitHub Actions)](#in-ci-github-actions)
- [Accepting findings](#accepting-findings)
- [Configuration: se-check.toml](#configuration-se-checktoml)
- [Command-line reference](#command-line-reference)
- [Try it on a deliberately vulnerable app](#try-it-on-a-deliberately-vulnerable-app)
- [Safety and privacy](#safety-and-privacy)
- [Limitations](#limitations)
- [Development](#development)

## Why

On Supabase the anon key ships with your frontend, so RLS is the only thing standing between it
and your data. The dangerous mistakes are the ones that look fine at a glance:

```sql
create policy "logged in users read documents" on documents
  for select to authenticated using (true);              -- every tenant reads every tenant

create policy "manage tasks" on tasks
  for all to authenticated using (auth.uid() is not null); -- "logged in" is not authorization

create policy "my tenant" on profiles for select to authenticated
  using (tenant_id = (auth.jwt() -> 'user_metadata' ->> 'tenant_id')::uuid);
  -- users can edit user_metadata themselves: pick any tenant you like
```

Supabase's own advisors catch some problems, such as RLS disabled or a mutable `search_path`.
se-check focuses on **multi-tenant isolation**: it knows which tables are tenant-scoped, which
roles actually hold privileges, and how Postgres really evaluates a policy.

## What it looks like

Against the deliberately vulnerable app in [`examples/vulnerable-app`](examples/vulnerable-app)
(output trimmed):

```text
$ se-check audit
se-check 0.1.0 · PostgreSQL 16.2 · schemas: public

CRITICAL  public.invoices  [rls-disabled]
  Row Level Security is disabled on a table the API can reach
  Without RLS these grants apply to every row of the table, whatever tenant or user it
  belongs to (anon: SELECT, INSERT, UPDATE, DELETE; authenticated: SELECT, INSERT, UPDATE,
  DELETE). Anyone holding a key for these roles can use them directly through the Data API.
  fix: alter table public.invoices enable row level security;
       -- then add policies for the access you actually want: with RLS on and no policies,
       -- the API sees no rows.

HIGH      public.delete_tenant(p_tenant uuid)  [definer-no-caller-check]
  SECURITY DEFINER function callable through the API without checking the caller
  It runs with its owner's privileges, so RLS does not apply inside it, and anon,
  authenticated can call it at /rest/v1/rpc/delete_tenant. Neither its body nor the
  functions it calls look at who is calling (auth.uid(), auth.jwt(), ...).
  fix: ...
       revoke execute on function public.delete_tenant(p_tenant uuid) from public, anon, authenticated;

HIGH      public.tasks  [permissive-policy]
  Policy "authenticated users manage tasks" does not restrict which rows can be read, inserted, updated or deleted
  Its condition only checks that the user is logged in, so every account passes it. It
  applies to: authenticated. The table has a `tenant_id` column, so users of one tenant
  reach the rows of every other tenant.
  ...

14 findings: 1 critical, 7 high, 2 medium, 4 low
Fine on purpose? se-check accept <check> <object> --reason "why"
```

With `--probe` it also catches what no definition shows. The UPDATE policy on `profiles` is
`using (id = auth.uid())`, which looks right, but nothing stops users from changing their own
role:

```text
$ se-check audit --probe
se-check 0.1.0 · PostgreSQL 16.2 · schemas: public
Probe: reached all 12 tables it could try, with 168 steps, all rolled back. Details at the
end.
...

HIGH      public.profiles  [probe-self-escalation]
  Users can set their own role
  Logged in as a member of tenant A, inside a transaction it rolled back, se-check updated
  her own row, setting role to 'admin'. UPDATE policies for authenticated: "users update
  their profile".
  fix: revoke update on public.profiles from authenticated;
       grant update (<the columns users may change>) on public.profiles to authenticated;
       -- then change role only server-side: the service role, an admin function, or a
       -- trigger that rejects other changes
...

24 findings: 2 critical, 14 high, 3 medium, 5 low
```

## Quick start

You need [uv](https://docs.astral.sh/uv/) and Python 3.10 or later. Install se-check once:

```bash
uv tool install git+https://github.com/devhardesian/se-check
```

Then, from your Supabase project folder:

```bash
se-check audit            # the local database, the one `supabase start` runs
se-check audit --linked   # the hosted project you linked with `supabase link`
se-check audit --probe    # the local database, trying the policies too
```

That's it: se-check reads the local port from `supabase/config.toml`, and for `--linked` the
address `supabase link` saved, so it only asks for the database password (hidden as you type).

Not using the Supabase CLI? Run `se-check audit` anywhere and paste a connection string when it
asks (Dashboard → Connect → Session pooler); the password is asked separately. In scripts and
CI, pass the connection string with `--dsn` or `$SE_CHECK_DSN`, and the password for
`--linked` with `$SUPABASE_DB_PASSWORD`.

## Static checks

| Check | Finds | Severity |
|---|---|---|
| `rls-disabled` | Tables in exposed schemas with RLS turned off | **critical** if an API role has grants on them, low otherwise |
| `permissive-policy` | Permissive policies that are always true, or only check that the user is logged in (`auth.uid() is not null`, `auth.role() = 'authenticated'`) | **high** on tenant-scoped tables and for UPDATE/DELETE; medium for open inserts, low for public reference data |
| `user-metadata-auth` | Policies, and helper functions they call, that read `user_metadata` | **high** |
| `auth-hook-exposed` | Auth hooks (e.g. `custom_access_token_hook`) that `anon`/`authenticated` can also call via `/rpc`, with any user id | **high** |
| `signup-trigger-metadata` | Triggers on `auth.users` (the usual `handle_new_user`) that copy a role, an admin flag, a plan or a tenant id out of `user_metadata`, which users choose at signup | **high** |
| `definer-no-caller-check` | `SECURITY DEFINER` functions callable via `/rpc` that never read the caller's identity, directly or through the functions they call | **high** |
| `definer-search-path` | `SECURITY DEFINER` functions without a fixed `search_path` | medium if callable via the API, low otherwise |

`se-check checks` prints the same list with a longer description of each check. How se-check
decides:

- **Privileges are real.** A policy only counts if the role it targets actually holds the
  privilege on the table.
- **Tenant-scoped tables** are the ones with a column like `tenant_id`, `org_id`,
  `organization_id`, `team_id`, `workspace_id`, `company_id` or `account_id`. Add yours with
  `--tenant-column` or `tenant_columns` in [`se-check.toml`](#configuration-se-checktoml).
- **Caller checks are followed.** A function checks its caller when it reads `auth.uid()` or
  `auth.jwt()`, or calls a helper that does, through any number of calls: your
  `has_permission()` counts by itself. Name helpers se-check cannot read (say, written in C)
  with `--guard`.
- **Auth hooks** are recognized by their grant to `supabase_auth_admin`, or by
  `[auth.hook.*]` in `supabase/config.toml`.

## Dynamic probe

The checks read definitions; `se-check audit --probe` also tries them. Inside one transaction,
which it always rolls back, it creates synthetic tenants A and B, users and rows in every
table, then acts as

- `anon`: a request carrying only the anon key, which ships with your frontend;
- `alice`, a member of tenant A, and `outsider`, a logged-in user of no tenant;
- `mallory`, a user who wrote tenant B into her own `user_metadata`, as anyone can with
  `supabase.auth.updateUser()` (only when your policies read tenants from there),

and tries what an attacker would, filtering on the primary key as the Data API does. Whatever
gets through is a finding:

| Check | Finds | Severity |
|---|---|---|
| `probe-anon-access` | Rows the anon key reads or changes | **critical** on tables of tenants or users and for updates and deletes; medium for inserts, low for reads of public data |
| `probe-cross-tenant-read` | Rows of tenant B that the others read | **high** |
| `probe-cross-tenant-write` | Rows of tenant B they update or delete, rows they insert into B, rows of A they move into B | **high** |
| `probe-cross-user-read` | On tables whose rows belong to a user (`notes.user_id`), bob's rows that alice reads | **high** |
| `probe-cross-user-write` | Bob's rows she changes, or rows she inserts in his name | **high** |
| `probe-self-escalation` | Alice setting her own `role`, `is_admin`, `plan`... to `'admin'`, `true`, `'enterprise'`, or moving her profile or membership into tenant B | **high** |

When a static check flagged the same hole on the same table, the finding says it confirms it.
On the example app the probe reports ten findings: eight confirm a static one, and two no
static finding names: users promoting themselves on `profiles`, and mallory reading tenant B's
`comments` through a helper that trusts `user_metadata`. Every `SAFE` table stays quiet.

### Personas that look like real users

If the personas didn't look like real users of your app, the policies would turn them all away
and the probe would see nothing. So se-check works out from your schema what a real user has:

- **Tenancy from foreign keys.** The tenant table is the one `tenant_id` and friends reference,
  in `public` or in a private schema; a memberships table gets `(alice, A)` and `(bob, B)` like
  any other synthetic row; a profile that a signup trigger creates gets its tenant.
- **JWT claims from your policies.** If a policy or helper reads
  `auth.jwt() -> 'app_metadata' ->> 'tenant_id'` (or `raw_user_meta_data` in auth.users), each
  persona carries their tenant there, and auth.users holds the same metadata.
- **Your access token hook**, from `[auth.hook.custom_access_token]` or a function granted to
  `supabase_auth_admin`, is called for each persona, as Supabase Auth does at sign-in.
- **Reference data it can't make up.** When a synthetic row can't be created (a CHECK rejects
  the made-up code of a plan, say), the rows that point at it don't give up: a nullable
  reference is left NULL, and a required reference to reference data (never to tenant or user
  rows) takes a row the table already holds. The database copies that row's key; se-check
  never sees it.

### Coverage: what "no findings" means

A probe that reached few tables proves little, so the report says how many it reached before
the findings, and warns when that is not all of them. Here every tenant needs a region, and the
regions table is empty:

```text
warning: the probe reached 4 of 12 tables (0 of 7 tenant-scoped), with 32 of 168 planned
steps: no probe finding on the other 8 says nothing about them. 8 of them because
private.regions got no synthetic row. See "Not reached" at the end.
```

The end of the report groups the tables it did not reach by the row that was missing, and says
what to do about it:

```text
Not reached (8 of 12 tables; fix them, or list them in [probe] skip_tables):
  private.regions: could not insert a synthetic row (23514, constraint regions_code_check):
    set values it accepts in [probe.values."private.regions"]
    8 tables needed its row: public.comments, public.documents, public.invoices,
      public.memberships, public.profiles and 3 more
```

It also lists the stand-ins it used, where the personas' JWT claims came from, and steps that
failed without saying anything about access. In CI, `--min-coverage 90` fails the job when the
probe reaches less than 90% of the tables it could try; tables you list in
`[probe] skip_tables` don't count against it.

### Helping it along

When your schema needs something se-check can't guess, say so in the `[probe]` section of
`se-check.toml`:

```toml
[probe]
skip_tables = ["public.events"]                         # leave these alone
claims = { app_metadata = { company = "{tenant}" } }    # a claim se-check can't recognize
membership = "insert into public.seats (user_id, tenant_id) values (%(user)s, %(tenant)s)"
privilege_columns = ["clearance"]                       # besides role, is_admin, plan, ...

[probe.values."public.invoices"]                        # values it can't make up
status = "draft"
```

Every key is described in [Configuration](#configuration-se-checktoml).

### Is it safe?

The probe writes, so it is opt-in, and it runs on local databases only (the local stack, CI, a
loopback address) unless you add `--probe-remote`.

- **Nothing stays.** Everything happens in one transaction that is rolled back, even if
  se-check crashes. Sequences still advance: ids get gaps.
- **Only its own rows.** It touches only rows it created, by the keys it generated. A synthetic
  row may point at an existing row of reference data, but only the database sees that row's
  key: se-check learns whether there was one, nothing else.
- **No data in the report.** It reports outcomes and SQLSTATEs, never values or error messages.
- **No waiting, no side effects.** Statements give up after 5 s, and after 1 s waiting for a
  lock. Tables whose triggers call `http` or `dblink`, which act outside the transaction, are
  skipped; `pg_net` and database webhooks only queue requests in a table, which the rollback
  empties.

## Use it from your AI agent (MCP)

**Claude Code**, from your project folder:

```bash
claude mcp add se-check -- se-check mcp --project "$PWD"
```

That audits the local database. For the hosted one, add `--linked` and put the password in the
server's environment:

```bash
claude mcp add se-check -e SUPABASE_DB_PASSWORD='...' -- se-check mcp --linked --project "$PWD"
```

Keep the default scope: `--scope project` would write the password into `.mcp.json`, in your
repository.

**Any MCP client** (Claude Desktop, Cursor, ...):

```json
{
  "mcpServers": {
    "se-check": {
      "command": "se-check",
      "args": ["mcp", "--project", "/path/to/your/supabase/project"]
    }
  }
}
```

| Tool | What it does |
|---|---|
| `audit_database(checks?, min_severity?)` | Runs the checks, returns structured findings with a suggested fix |
| `probe_database(checks?, min_severity?)` | The same, plus the [dynamic probe](#dynamic-probe) and its coverage; only with `se-check mcp --probe`, on a local database |
| `list_checks()` | Lists the available checks |

Then ask your agent something like *"after every migration that touches tables, policies or
functions, run `audit_database` and fix critical and high findings before you finish"*.

To let it try the policies on the local stack too, start the server with `--probe`
(`claude mcp add se-check -- se-check mcp --probe --project "$PWD"`) and ask for
`probe_database` after policy changes. The server refuses `--probe` for hosted databases.

The server reads [`se-check.toml`](#configuration-se-checktoml) on every call, so edits apply
without a restart. The agent sees accepted findings with their reason, and is told that
accepting a finding is the team's call, not its own.

## In CI (GitHub Actions)

Audit the database your migrations build, on every pull request, and get the findings as
annotations on the migration that created each object:

```yaml
name: se-check
on: pull_request

permissions:
  contents: read
  security-events: write   # to upload the SARIF report

jobs:
  rls:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: supabase/setup-cli@v1
      - run: supabase db start   # local database, built from supabase/migrations
      - uses: devhardesian/se-check@v0
        with:
          probe: "true"          # optional: try the policies too
          min-coverage: "90"     # optional: fail if the probe reaches less than 90% of tables
      - uses: github/codeql-action/upload-sarif@v3
        if: always()            # upload the annotations even when se-check fails the job
        with:
          sarif_file: se-check.sarif
```

| Input | Default | |
|---|---|---|
| `project` | `.` | Supabase project folder, the one with `supabase/config.toml` |
| `dsn` | | Connection string of another database, from a secret; empty audits the project's local database |
| `fail-on` | `high` | Fail the job on findings at least this severe (`critical`, `high`, `medium`, `low`, `info` or `never`) |
| `min-severity` | `low` | Leave out findings below this severity |
| `sarif-file` | `se-check.sarif` | Where to write the SARIF report; empty to skip it |
| `probe` | `"false"` | `"true"` also runs the [dynamic probe](#dynamic-probe) |
| `min-coverage` | | With `probe`: fail when the probe reaches less than this percentage of the tables it could try |
| `args` | | Extra arguments for `se-check audit`, e.g. `--schema api` |

Outside GitHub, `se-check audit --sarif report.sarif` writes the same file.

## Accepting findings

Some findings are fine on purpose: a pricing table everyone may read, say. Record them, with
the reason, and they stop cluttering the report and failing CI:

```bash
se-check accept permissive-policy public.plans --reason "Pricing is public on the landing page."
```

That writes `se-check.toml` next to your `supabase/` folder: commit it, so the reasons get
reviewed like code. A reason is mandatory, accepted findings are still listed (separately, with
their reason), and entries that stop matching anything are reported so the file doesn't rot.

## Configuration: se-check.toml

One file next to your `supabase/` folder holds the settings and the accepted findings. Every
key is optional, and command-line options win over the file.

```toml
schemas = ["public", "api"]           # schemas the Data API exposes (default: public)
api_roles = ["anon", "authenticated"] # roles API requests run as
tenant_columns = ["clinic_id"]        # mark tables as tenant-scoped, besides tenant_id & co.
guards = ["check_access"]             # functions that check the caller in a way se-check can't read

[[accept]]
check = "permissive-policy"
object = "public.plans"
policy = "plans are public"           # optional: only this policy of the table
reason = "Pricing is public on the landing page."

[probe]
skip_tables = ["public.events"]
claims = { app_metadata = { company = "{tenant}" } }
membership = "insert into public.seats (user_id, tenant_id) values (%(user)s, %(tenant)s)"
privilege_columns = ["clearance"]

[probe.values."public.invoices"]
status = "draft"
```

| `[probe]` key | |
|---|---|
| `skip_tables` | Tables the probe leaves alone. They don't count against its coverage, and the report lists them as left out. |
| `values."schema.table"` | Values for columns se-check can't make up, written as text: Postgres casts them to the column's type. |
| `claims` | Extra JWT claims for every logged-in persona, applied last. `"{user}"` becomes the persona's user id, `"{tenant}"` their tenant's id. |
| `membership` | SQL run for alice and bob when the catalog can't show how users join a tenant, with `%(user)s` and `%(tenant)s`. |
| `privilege_columns` | Columns that decide privileges, besides `role`, `roles`, `user_role`, `app_role`, `is_admin`, `admin`, `is_superuser`, `superuser`, `permissions`, `plan` and `tier`. |

## Command-line reference

| Command | |
|---|---|
| `se-check audit` | Audit a database and print the findings |
| `se-check accept <check> <object> --reason "..."` | Record a finding as fine on purpose (`--policy` for one policy of a table) |
| `se-check checks` | List the checks |
| `se-check mcp` | Start the MCP server over stdio |

| Option | Default | |
|---|---|---|
| `--project` | current folder | Supabase project folder (the one with `supabase/config.toml`, searched upwards) |
| `--config` | `se-check.toml` in the project | Settings and accepted findings |
| `--linked` | | Audit the hosted project linked with `supabase link` instead of the local database |
| `--dsn` | `$SE_CHECK_DSN` | Connection string of any Postgres database |
| `--schema` | `public` | Schemas exposed through the Data API (repeatable) |
| `--api-role` | `anon`, `authenticated` | Roles API requests run as (repeatable) |
| `--tenant-column` | built-in list | Extra column marking a table as tenant-scoped (repeatable) |
| `--guard` | | Function that checks the caller in a way se-check cannot read, e.g. written in C (repeatable) |
| `--check` | all | Run only these checks (repeatable, `audit` only) |
| `--min-severity` | `low` | Hide less severe findings (`audit` only) |
| `--fail-on` | `high` | Exit with status 1 when a finding is at least this severe; `never` to disable (`audit` only) |
| `--probe` | | Also run the [dynamic probe](#dynamic-probe) (`audit`); offer `probe_database` (`mcp`) |
| `--probe-remote` | | Let `--probe` run on a database that is not on this machine (`audit` only) |
| `--min-coverage` | | With `--probe`: exit with status 1 when the probe reaches less than this percentage of the tables it could try (`audit` only) |
| `--format` | `text` | `text`, `json` or `sarif` (`audit` only) |
| `--sarif` | | Also write a SARIF report to this file (`audit` only) |
| `--no-color` | | Plain text output; `$NO_COLOR` does the same (`audit` only) |

| Exit status | |
|---|---|
| 0 | No finding at `--fail-on` or above, and coverage at `--min-coverage` or above |
| 1 | A finding at `--fail-on` or above, or the probe below `--min-coverage` |
| 2 | Usage error, broken `se-check.toml`, or the database could not be audited |

Environment: `SE_CHECK_DSN` (connection string), `SUPABASE_DB_PASSWORD` (password for
`--linked`, the variable the Supabase CLI reads too), `NO_COLOR`.

## Try it on a deliberately vulnerable app

[`examples/vulnerable-app`](examples/vulnerable-app) is a small multi-tenant schema in which
every object is tagged `VULN` or `SAFE`. Spin it up and audit it:

```bash
docker compose up -d
se-check audit --dsn postgresql://postgres:postgres@localhost:54329/postgres
```

No Docker? `uv run python scripts/playground.py` starts a throwaway Postgres with the same
schema and opens a menu: run the audit and the probe with one keystroke, and read what each
part of the command means, how to run it yourself, how to point it at your own database and how
to hook it up to an AI agent. Quitting deletes the database.

## Safety and privacy

- **Metadata only.** se-check reads the system catalog (tables, grants, policies, function
  definitions), never the contents of your tables. Findings name objects, not data.
- **Read-only.** Every query of the audit runs in a read-only transaction with a 30 s
  statement timeout. Server-side prepared statements are off, so Supabase's transaction pooler
  works. The one exception is `--probe`, which writes synthetic rows in a transaction it always
  rolls back: see [Is it safe?](#is-it-safe).
- **MCP.** The connection string comes from the server configuration, never from the model.
  `audit_database` and `list_checks` are annotated read-only; `probe_database`, there only with
  `--probe` on a local database, says it writes. Policy expressions quoted in findings come
  from the database: the server tells the agent to treat them as data, not instructions.

## Limitations

- **The probe tries tables, not functions.** It does not call `/rpc` functions yet.
- **The probe does not read CHECK constraints.** A made-up value a CHECK rejects means no
  synthetic row for that table (the coverage says so, and what to set in `[probe.values]`); an
  escalation value it rejects shows up as an inconclusive step.
- **One synthetic row per table and tenant.** A table whose CHECK compares two references to
  the same table (`a_id <> b_id`) gets no row, and tables without a primary key get rows but no
  steps.
- **Claims and privilege columns are recognized by name.** The probe infers only the JWT
  claims that name a tenant (others come from your access token hook or `[probe] claims`), and
  privilege columns by their English names (add yours with `privilege_columns`).
- **Caller checks are recognized by name:** `auth.uid()`, `auth.jwt()`, helpers that read them
  and `--guard` functions. A function can call `auth.uid()` and still get the logic wrong.
- **Helpers are followed one level deep for `user_metadata`:** a policy → helper → helper
  chain that reads it is not caught yet.

## Development

```bash
uv sync
uv run pytest            # starts a throwaway Postgres via pgserver, or uses $SE_CHECK_TEST_DSN
uv run ruff check . && uv run ruff format --check .
```

Database tests need a Postgres superuser on a disposable server: `pgserver` (installed with the
dev dependencies on Python ≤ 3.12) or the server in `SE_CHECK_TEST_DSN`, which CI uses. Without
either they are skipped.

Checks are pure functions over a catalog snapshot (`src/se_check/catalog.py`), so most tests
need no database. A new check needs unit tests in `tests/test_checks*.py` **and** `VULN`/`SAFE`
cases in the example app, listed in `tests/test_integration.py`: that test fails on false
positives as well as misses. The probe is split the same way: its planner, claims and rules are
pure (`tests/test_probe_plan.py`, `tests/test_probe_claims.py`, `tests/test_checks_probe.py`),
and only `probe/execute.py` touches the database (`tests/test_probe_integration.py`).

What changed in each version is in [CHANGELOG.md](CHANGELOG.md).

## License

[MIT](LICENSE)

## Test push

Push verification with account **DeepDruido** — 2026-11-12.

# Dynamic probe: design

Status: design accepted 2026-10-05; coverage reporting and stand-ins for missing reference rows
added 2026-10-19, after the first field test (see [Decisions](#decisions)). Phases 0, 1 and 2
are implemented; what was dropped or left is listed under [Phases](#phases).

Contents: [Goal](#goal) · [Safety model](#safety-model) ·
[Verified semantics](#verified-semantics) · [Architecture](#architecture) ·
[Coverage](#coverage) · [Interfaces](#interfaces) · [Tests](#tests) · [Phases](#phases) ·
[Notes from the implementation](#notes-from-the-implementation) · [Risks](#risks) ·
[Decisions](#decisions)

## Goal

The static checks read definitions. Some holes only show when Postgres evaluates them, e.g.
`profiles` in the example app: an UPDATE policy `using (id = auth.uid())` looks right, but lets
users set their own `role` to `admin`. The probe asks Postgres directly: inside a transaction
that is always rolled back, it creates synthetic tenants, users and rows, then acts as `anon`
and as users of two tenants and records what each of them can read and write.

Questions it answers, per table exposed through the Data API:

- Can a user of tenant A read, update or delete a row of tenant B, or insert one into B?
- Can a user reach another user's rows, on tables whose rows belong to a user?
- Can a user move their own row to another tenant?
- Can a logged-in user with no tenant at all reach tenant rows?
- Can `anon` reach rows?
- Can a user change the columns that decide their own privileges (role, admin flag, plan,
  tenant)?

Non-goals for now: RPC functions (phase 3), views, Storage, Realtime, Edge Functions, and
completeness. A clean probe is evidence, not proof.

## Safety model

The probe writes, which the rest of se-check never does. These invariants are the feature;
the implementation and its tests are built around them.

1. **One transaction, always rolled back.** `conn.transaction(force_rollback=True)`, and no code
   path calls `commit`. A crash or a dropped connection also rolls back: the server never
   commits an open transaction on its own.
2. **Only rows it created.** Every statement run as a persona targets a synthetic row by the
   primary key the probe generated. Reads are `select exists(... where pk = $1)`; never
   `count(*)` or an unfiltered select over a table. The "never read table contents" rule holds.
   A synthetic row may *point at* an existing row of reference data (see Fixtures), but the
   database copies that row's key into a transaction-local setting: se-check only learns
   whether there was one, and never reads such a column back.
3. **Findings are metadata.** Table, command, persona, policy names, SQLSTATE, constraint name.
   Never the text of a database error: `message_detail` and messages raised by triggers can
   contain values, and `message_primary` is localized anyway.
4. **Short timeouts.** `SET LOCAL statement_timeout = '5s'`, `lock_timeout = '1s'`, so the probe
   gives up instead of queueing behind application locks.
5. **What escapes a rollback.** Sequences advance (ids get gaps); functions from `http`,
   `dblink` or `postgres_fdw` act outside the transaction; session advisory locks outlive it.
   The planner skips tables whose triggers reach such functions (through the same call-graph
   walk the caller checks use) and lists them as skipped. `pg_net` and Supabase database
   webhooks queue requests in a table, so they should roll back too (to verify).
6. **Opt-in, local by default.** A plain `audit` never probes. Probing a non-local database
   needs `--probe-remote` on the command line; the MCP server never probes one.

## Verified semantics

Spike on PostgreSQL 16 (pgserver, superuser session) loaded with `examples/vulnerable-app`,
2026-10-05:

| Behavior | Result |
|---|---|
| `SET LOCAL ROLE authenticated` + `set_config('request.jwt.claims', ..., true)` | `auth.uid()` returns the persona; RLS applies even though the session user is a superuser |
| `force_rollback=True` | nothing persists; role and claims are back to the session's afterwards |
| Error inside a savepoint | recoverable, the outer transaction goes on |
| Nested `conn.transaction(force_rollback=True)` | a savepoint that undoes a step even when it succeeded |
| UPDATE/DELETE on a row hidden by RLS | succeeds with rowcount 0, no error |
| INSERT failing WITH CHECK | `42501` "new row violates row-level security policy" |
| INSERT without the grant | `42501` too: tell them apart through the catalog's privileges, not the message |
| UPDATE whose WHERE reads columns, row hidden by SELECT policies | rowcount 0; the same UPDATE without WHERE updates the row |
| UPDATE whose new row fails a SELECT policy | `42501` |
| Seeding a FORCE RLS table | works as a BYPASSRLS role (`service_role`), fails as a non-superuser owner |
| INSERT into `auth.users` | fires the app's triggers (`handle_new_user` created the profiles) |
| RPC `delete_tenant(B)` as alice | ran, then failed on a foreign key (`23503`): a constraint error is not a denial |

The finding that shapes the design: **persona realism decides what the probe sees.** Alice
promoting herself to admin on `profiles` returned rowcount 0 with bare claims, because the SELECT
policy compares `profiles.tenant_id` with `user_metadata.tenant_id` and neither was set. With
her profile linked to tenant A and `user_metadata.tenant_id` in her JWT, as the app would do,
the same UPDATE returned rowcount 1. A probe with half-provisioned personas reports false
negatives. See [Tenancy model](#tenancy-model).

Phase 0, 2026-10-05. No Docker on the development machine, so the Supabase side comes from the
migrations of `supabase/postgres` and `supabase/auth`, replayed on pgserver with a session role
shaped like Supabase's `postgres`:

| Fact | Source | Consequence |
|---|---|---|
| `postgres` is `NOSUPERUSER ... BYPASSRLS` | `10000000000000_demote-postgres.sql` | seed as the session user, FORCE RLS tables included |
| `postgres` is a member of `anon`, `authenticated`, `service_role` | `20230201083204_grant_auth_roles_to_postgres.sql` | `SET ROLE` to every persona works |
| `postgres` holds ALL on the tables of `auth`, now and future | `20211115181400_update-auth-permissions.sql` | synthetic users go straight into `auth.users` |
| `authenticator` preloads `safeupdate` | `20260413000000_fix-authenticator-session-preload-libraries.sql` | API UPDATE/DELETE always carry a WHERE: the PostgREST shape is the only one to probe |
| `auth.uid()`, `auth.role()`, `auth.email()` read `request.jwt.claims` (legacy `request.jwt.claim.*` first) | `supabase/auth` `20220224000811_update_auth_functions` | setting `request.jwt.claims` is enough, as PostgREST does |
| A NOSUPERUSER BYPASSRLS session role under `SET LOCAL ROLE authenticated` is subject to RLS | pgserver | same as with a superuser |
| `SET LOCAL ROLE` and claims set inside a savepoint are undone by rolling it back | pgserver | each step impersonates inside its savepoint; no explicit reset |
| On INSERT, RLS is checked before unique constraints | pgserver | a duplicate key does not mask a denial |
| `set_config(name, value, true)` made before a savepoint survives rolling it back, and `current_setting()` reads it after `SET LOCAL ROLE authenticated` | pgserver, 2026-10-19 | an existing row's key, copied once while seeding, serves every step |
| A foreign key check ignores RLS on the referenced table | pgserver, 2026-10-19 | a persona's insert may point at reference data it cannot read |

Seeding role: the session user when it is a superuser or BYPASSRLS (Supabase's `postgres` is),
else `service_role` when the session user may become it, else the session user (tables it cannot
seed are skipped).

Not verified, covered by the local-by-default rule: `SET LOCAL` through the transaction pooler
(transaction-scoped, so it should hold), and `pg_net` requests queued by a rolled-back
transaction never being sent.

## Architecture

Same split as the static checks: database access in one module, everything else pure.

```text
          read-only transaction                         rollback-only transaction
dsn ─► load_catalog ─► Catalog ─► plan_probe ─► ProbePlan ─► execute ─► Observations ─► interpret ─► Findings
                                    (pure)                     (DB)                     (pure)
                                       └──────────── skips (coverage) ─────────────────────┘
```

Package `src/se_check/probe/`:

| Module | Pure | Role |
|---|---|---|
| `model.py` | yes | Personas, scenarios; values of synthetic rows (`Text`, `UserId`, `RowValue`, and the stand-ins `Null` and `ExistingRow`); `RowRecipe`, `Step`, `Outcome`, `Observation`, `Skip`, `StandIn`, `Tenancy`, `ProbePlan`, `ProbeCoverage` |
| `tenancy.py` | yes | `infer_tenancy`: the tenant table, tenant-scoped tables, tables of rows owned by a user |
| `claims.py` | yes | `inferred_claims`: the tenant claims the policies and their helpers read |
| `fixtures.py` | yes | `build_recipe`: one synthetic row of a table for a side; `synthetic_value` and `escalation_values` by type |
| `plan.py` | yes | `plan_probe(catalog, config, probe) -> ProbePlan`: fixtures in insert order, steps, skips with their cause, the coverage targets, the trigger scan, the access token hook |
| `execute.py` | no | The only module that touches the database: one rolled-back transaction, a rolled-back savepoint per step |
| `rules.py` | yes | `PROBE_RULES`, `interpret`, `link_confirmations` |
| `__init__.py` | | `run_probe(dsn, catalog, config, probe) -> ProbeResult` (findings and coverage); `shown_skips` picks the skips worth reporting |

Elsewhere:

- `catalog.py`: `Column` (type, base type and category, length, nullability, default, identity,
  generated, enum labels), `ForeignKey`, `TableTrigger`; `Table` gains `column_details`,
  `primary_key`, `foreign_keys` and `triggers`. `Catalog.support_tables` holds the tables of the
  project's other schemas (`private`, ...): the checks ignore them, the probe fills them.
- `checks/base.py`: `Rule` (id, title, description, max severity); `Check(Rule)` adds `run`.
  `se_check/rules.py` holds `ALL_RULES` (static, then probe) for SARIF, `accept`, settings
  validation and `se-check checks`, and `select_rules` for `--check`. The registry lives outside
  `checks/` so that the checks never import the probe. `config.PRIVILEGED_NAMES` is shared with
  `signup-trigger-metadata`.
- `audit.py`: `run_audit(..., probe=True)` loads the catalog read-only, then `run_probe` opens
  its own connection (`db.connect_for_probe`, closed without a commit). Probe findings join the
  static ones before the acceptances. `AuditReport.probe` holds the coverage; JSON has a `probe`
  key, null without `--probe`.
- `connection.py`: `Target.local`, `is_local()`, `access_token_hook()` (from
  `[auth.hook.custom_access_token]`). `report.py`: the coverage line under the title and the
  coverage section at the end (see [Coverage](#coverage)). `server.py`: `probe_database`.

### Outcomes

| Outcome | When |
|---|---|
| `ALLOWED` | SELECT returned true; UPDATE, DELETE or INSERT touched a row |
| `FILTERED` | the statement ran and touched nothing: RLS hid the row (or a trigger dropped it) |
| `DENIED` | `42501`, a WITH CHECK or a missing privilege |
| `INCONCLUSIVE` | any other SQLSTATE: constraint, trigger exception, timeout |

The design had two denials, by policy and by grant. Both raise `42501` and the message is
localized, and steps only run for privileges the catalog shows, so `DENIED` is one outcome.

Before anything else the executor checks that the session user can `SET ROLE` to every
persona's role: if it cannot, every step would fail with `42501` and read as a denial, so the
probe stops and says why.

### Personas

| Persona | Role | Catches |
|---|---|---|
| `anon` | `anon` | what the anon key in the frontend can do |
| `alice` | `authenticated` | the attacker, member of tenant A; owns side A of tables of rows owned by a user |
| `bob` | `authenticated` | owns the target rows (tenant B, side B); never acts |
| `outsider` | `authenticated` | `auth.uid() is not null` policies: anyone who signs up |
| `mallory` | `authenticated` | a user of no tenant who wrote tenant B into her own user_metadata, as anyone can with `supabase.auth.updateUser()`; only acts when the policies read tenants from user_metadata |

An anonymous sign-in persona (`is_anonymous: true`) was planned and dropped: anything it can do,
the outsider can do too, so it would only change a finding's wording, and whether anonymous
sign-ins are on is not in the database.

### Claims

Built once per persona, before the steps:

1. What PostgREST would set: `{"iss", "role"}` for anon; for logged-in personas also `sub`,
   `aud`, `email`, `app_metadata` (provider email), `user_metadata` and `is_anonymous: false`.
2. The tenant claims the policies and their helpers read (`claims.py`): paths after
   `auth.jwt()`, `current_setting('request.jwt.claims', true)` or the `raw_*_meta_data` columns
   of auth.users, through `->`, `->>` and `#>>`, in deparsed policies and in function bodies.
   A key named like a tenant column gets the persona's tenant id; its plural (`tenant_ids`) a
   list holding it; other claims (roles, flags) are left out, so no persona gets a privilege
   by accident. This is what makes holes behind `user_metadata.tenant_id` visible (the spike).
   Mallory gets tenant B wherever `user_metadata` is concerned.
3. `[probe] claims`, with `"{user}"` and `"{tenant}"` replaced (a `"{tenant}"` the persona
   lacks is dropped).
4. app_metadata and user_metadata are written to auth.users (`raw_app_meta_data`,
   `raw_user_meta_data`), which the JWT mirrors and some helpers read.
5. The custom access token hook, when there is one (`[auth.hook.custom_access_token]` in
   config.toml, else a function granted to `supabase_auth_admin` with `access_token` in its
   name and a jsonb argument, never one that escapes the transaction), is called with
   `{"user_id", "claims", "authentication_method"}`, as Supabase Auth does at sign-in; the
   claims it returns replace the persona's.
6. `[probe] claims` again: the configuration has the last word.

The coverage lists where the claims came from.

### Tenancy model

- **Tenant table**: the table that single-column foreign keys from tenant columns reference
  most, in any project schema.
- **Tenant-scoped tables**: the tenant table; tables with a tenant column; tables with a NOT
  NULL foreign key to a tenant-scoped table, transitively (comments of a project).
- **Tables of rows owned by a user**: not tenant-scoped, with a NOT NULL foreign key to
  `auth.users` (`notes.user_id`). They get two rows, alice's (side A) and bob's (side B). A
  nullable reference (`created_by`) says who wrote a row, not whose it is.
- **Membership**: no special case. Every tenant-scoped table gets a synthetic row per tenant,
  owned by that tenant's persona (foreign keys to `auth.users` take the owner's id), so a
  memberships table gets `(alice, A)` and `(bob, B)` like any other row. Layouts the catalog
  cannot show take `[probe] membership`, run for alice and bob.
- **Rows keyed by a user** (the primary key includes a foreign key to `auth.users`, e.g.
  `profiles`): upserted, so the row a signup trigger made gets the persona's tenant. These are
  identity rows: they say who the user is.
- **Other schemas**: tables of the project's other schemas are filled when they hold tenancy
  (a `private.memberships` that helpers read) or when filled rows point at them; the API cannot
  reach them, so no step runs there. Their skips are reported only when they explain why a
  target was not reached, or which stand-in another row took.
- **No tenant table**: tenant columns still count; tenant ids are made-up uuids (uuid and text
  columns only).
- **Users**: one `auth.users` row per logged-in persona (`id`, and `email`, `aud`, `role` when
  the columns exist), inserted as the session user: signup triggers run.
- **Seeding role**: as in the verified semantics above.

### Fixtures

A `RowRecipe` plans one synthetic row without the database:

- `[probe.values."schema.table"]` comes first;
- foreign keys point at the planned row of the same side, else at the table's side-less row;
  nullable references are set when that row exists, NULL otherwise; a NOT NULL reference to a
  table se-check does not load (a managed schema), or without a row, skips the table;
  self-references must be nullable; cycles are broken with NULLs;
- when the row a reference should point at is missing, at planning or because its insert
  failed (a CHECK rejected a made-up code), the reference takes a stand-in instead of skipping
  the table: NULL when every column of it may be NULL; otherwise, when the parent is reference
  data se-check knows (neither tenant- nor user-scoped), a row the parent already holds. Never
  for the tenant column, which says whose the row is, nor for primary key columns, which steps
  address rows by. The executor copies the existing row's key into transaction-local settings
  (`select bool_and(set_config('se_check.ref_N_i', key::text, true) is not null) from (... order
  by key limit 1)`), as the seeding role, once per parent, before any step; values then read
  `current_setting('se_check.ref_N_i')::<column type>`. Only the boolean comes back, and such
  columns are never in RETURNING. Stand-ins are listed in the coverage, under the reason the
  parent's row was missing;
- the tenant column takes the tenant's id; columns with a default, identity or generation are
  left alone; other NOT NULL columns get a value by type (`se-check-<hex>` trimmed to
  `varchar(n)`, random numbers, `false`, `now`, `0` for intervals, `192.0.2.1`, `{}` for arrays
  and json, the first enum label, a domain's base type), or skip the table, naming the column
  to set in `[probe.values]`;
- values travel as untyped text parameters, which Postgres casts to the column's type;
- fixtures return their primary key and the columns other tables reference; tables come after
  the tables they point at, the tenant table first;
- tables without a primary key get rows too (memberships often have none), but no steps: there
  is no key to address their rows by, as PostgREST would.

### Scenarios

| Scenario | Persona | Statement | Finding when |
|---|---|---|---|
| cross-tenant read | alice, outsider, mallory | `select exists(select 1 from t where pk = B)` | true |
| cross-tenant update / delete | alice, outsider, mallory | `update t set c = c where pk = B`, `delete ...` | rowcount > 0 |
| cross-tenant insert | alice, outsider, mallory | insert a fresh row of tenant B, owned by the actor | succeeds |
| tenant hop | alice | `update t set tenant_id = <tenant B> where pk = A` | rowcount > 0 |
| cross-user read / update / delete | alice, outsider | the same on bob's row | true / rowcount > 0 |
| cross-user insert | alice, outsider | insert a row in bob's name | succeeds |
| self-escalation | alice | `update t set role = 'admin' where pk = <her own row>` | rowcount > 0 |
| anon access | anon | the four commands on B's row, or the row of a table without sides | succeeds |

- A step runs only when its role holds the privilege, per the catalog.
- Logged-in personas don't insert into the tenant table: creating a tenant of your own is not
  reaching someone else's.
- Self-join falls out of the cross-tenant insert: on the memberships table it is alice adding
  herself to tenant B.
- UPDATE in the crossing scenarios sets a column that is neither a key nor a reference to itself.
- **Tenant hop** moves alice's row of tenant A through its tenant column, or through the
  reference that makes it tenant-scoped (`comments.project_id`). On an identity row (her
  profile, her membership) moving it is joining tenant B: that counts as self-escalation.
- **Self-escalation** runs on alice's own rows: rows holding her user id, and her tenant's row
  in the tenant table. Columns: `config.PRIVILEGED_NAMES` (role, roles, user_role, app_role,
  is_admin, admin, is_superuser, superuser, permissions, plan, tier) and `[probe]
  privilege_columns`, never keys or references. Values (`escalation_values`): enum labels like
  admin/owner/super/staff/manager, else the last label; `true`; `'admin'` and `'owner'`, or
  `'enterprise'` and `'pro'` for plan and tier; `{admin}` for arrays; the type's maximum for
  integers.

### Rules and findings

| Rule | Severity |
|---|---|
| `probe-anon-access` | critical on tables with sides (tenants or owners) or for UPDATE/DELETE; medium for inserts and low for reads elsewhere |
| `probe-cross-tenant-read` | high |
| `probe-cross-tenant-write` | high (update, delete, insert, tenant hop) |
| `probe-cross-user-read` | high |
| `probe-cross-user-write` | high |
| `probe-self-escalation` | high |

One finding per rule and table, grouping commands and personas. What anon can do is not
reported again for logged-in personas; self-escalation is never folded. When only mallory got
through, the finding says the policies take the tenant from user_metadata and the remediation
starts there; when the outsider got through too, mallory adds nothing to the wording. Evidence:
commands, the statements tried (placeholders for values), personas, the permissive policies
that apply to that role and command, the columns (self-escalation), and `confirms` when a
static finding about the same hole names the same table: rls-disabled and permissive-policy for
every crossing rule and anon access, user-metadata-auth for the cross-tenant ones, nothing for
self-escalation, which no static check sees. Remediation: enable RLS when it is off; otherwise
`alter policy` lines for those policies; for self-escalation, column-level UPDATE grants.

## Coverage

A clean probe only speaks for the tables it reached. The field test of 2026-10-09
([docs/field-tests](../field-tests/2026-10-09-real-multi-tenant-app.md)) showed why that must
be loud: 3 of 67 tables reached looked like a clean run.

`ProbeCoverage` holds: tenancy in words; personas and how they were set up; where their claims
came from; the targets, the tables reached and the steps run against those planned; skips,
each with its reason and the table whose missing row caused it (`Skip.cause`); stand-ins;
inconclusive steps with their SQLSTATE; the number of statements; or why the probe was
blocked.

- **Targets** (`ProbePlan.targets`) are the exposed tables where some persona has something to
  try, given the privileges its role holds, minus `[probe] skip_tables`. Those are listed apart
  as left out: skipping is a reviewed decision, like accepting a finding.
- **Reached** means at least one step ran to a conclusive outcome (allowed, filtered or
  denied).
- **Skips worth showing** (`shown_skips`): those of targets, the chain of causes behind them
  in any schema, the parents of stand-ins, and setup that failed (users, membership, hook).

The text report puts one line under the title, before the findings: dim when every target was
reached, a warning otherwise, naming the missing row behind most of the misses. At the end it
groups the targets not reached by root cause, with a hint per SQLSTATE (`[probe.values]` for a
CHECK, `skip_tables` for a duplicate key, the lock for `55P03`), lists the stand-ins under the
reason their row was missing, and repeats the warning above the summary. JSON has `complete`,
`tables`, `tenant_scoped_tables`, `steps`, `not_reached`, `left_out` and `stand_ins`;
`--min-coverage` fails the run below a share of targets reached.

## Interfaces

- **CLI**: `se-check audit --probe` adds probe findings to the same report, exit code and SARIF.
  It refuses a non-local target unless `--probe-remote` is given, and `--linked --probe` is
  refused before the password prompt. `--check` takes probe rules too; naming one without
  `--probe`, or `--probe-remote` or `--min-coverage` without `--probe`, is a usage error.
  `se-check checks` lists the probe rules under their own heading.
- **`se-check.toml`**:

  ```toml
  [probe]
  skip_tables = ["public.events"]
  claims = { app_metadata = { company = "{tenant}" } }
  membership = "insert into public.seats (user_id, tenant_id) values (%(user)s, %(tenant)s)"
  privilege_columns = ["clearance"]

  [probe.values."public.invoices"]
  status = "draft"
  ```

  `[[accept]]` takes probe rule ids like any other check.
- **MCP**: `se-check mcp --probe` adds `probe_database(checks?, min_severity?)`: the audit plus
  the probe, annotated `read_only_hint=False`, `destructive_hint=False`, `idempotent_hint=True`.
  `audit_database` stays read-only and refuses probe rule ids. `--probe` on a non-local target
  (or with `--linked`) exits with an error at startup: no prompt, stdin carries the protocol,
  and no `--probe-remote` for MCP. `list_checks` names the probe rules when the tool is on, and
  the server instructions mention it.
- **GitHub Action**: inputs `probe: "true"` and `min-coverage`. CI audits the database
  `supabase db start` builds, which is local.
- **Playground**: option 5 runs `audit --probe`, option 6 explains it.

## Tests

- `tests/test_probe_plan.py`: tenancy (tenants, users, private schemas), synthetic values and
  recipes, stand-ins and where they are refused, fixture order, steps per scenario, own-row
  steps, skips and their causes, coverage targets, the trigger scan, the hook.
- `tests/test_probe_claims.py`: claim paths in deparsed policies and function bodies; which
  claims are inferred.
- `tests/test_checks_probe.py`: each rule from hand-made observations, positive and negative;
  folding, mallory's wording, confirmations, acceptances, `--check` selection.
- `tests/test_probe_integration.py`, on a real server: the golden `EXPECTED_PROBE` (in
  `tests/test_integration.py`), as a superuser and as a role shaped like Supabase's `postgres`
  (fixture `supabase_role_dsn`); the database is unchanged afterwards; a secret in real rows
  never reaches the report; a locked table is skipped after `lock_timeout`; a table whose
  trigger calls `http_post()` is never touched; a session that cannot `SET ROLE` blocks the
  probe; inferred, configured and hook claims; tenancy in a private schema; the field test's
  cascade (an empty reference table every tenant needs) named as the root cause; an existing
  reference row standing in without its value reaching the report.
- Server, CLI, settings, connection and report tests cover `probe_database`, the options
  (`--min-coverage` included), `[probe]`, `Target.local`, the hook in config.toml, and the
  coverage line, groups and stand-ins in the report and in JSON.

## Phases

0. **Spikes.** Done: Postgres semantics on pgserver, Supabase's roles and functions from its
   migrations. Not done: a live Supabase stack (no Docker access on the development machine).
1. **MVP.** Done 2026-10-05.
2. **Realism.** Done 2026-10-05: inferred claims, the access token hook, metadata in
   auth.users, mallory, self-escalation, tenant hop, rows owned by a user, other schemas,
   `probe_database`, the Action input. Dropped: the anonymous sign-in persona (see Personas).
   Left: unique keys for tables without a primary key (Supabase tables nearly always have one;
   such tables get rows but no steps), and CHECK constraints as a source of escalation values
   (a value they reject shows up as an inconclusive step).
   - **Coverage and stand-ins.** Done 2026-10-19, from the field test: coverage before the
     findings, skips grouped by root cause, `--min-coverage`, stand-ins for missing reference
     rows (decisions 6 and 7). Left from the same field test: values that satisfy simple CHECK
     constraints, NULL in `[probe.values]`, a second synthetic row per table, singleton
     tables, privilege columns found by more than their name, and saying which role each
     persona has.
3. **Further.** RPC: call `SECURITY DEFINER` functions as alice with B's ids, observe the effect
   as admin. The observations are an access matrix (roadmap: access-matrix snapshots) and each
   step maps to a pgTAP assertion (roadmap: pgTAP export).

## Notes from the implementation

- The static audit's `pg_policies` query (`pg_get_expr`) takes an ACCESS SHARE lock: behind an
  ACCESS EXCLUSIVE lock (a migration in progress) the whole audit waits until its 30 s
  statement timeout. Not fixed yet; the lock test uses a SHARE lock for that reason.
- `ruff format --check` also formats Python blocks inside Markdown: keep code samples in docs
  formatted, or leave them out.
- If the session user cannot `SET ROLE` to a persona's role, every step fails with `42501` and
  would read as a denial: a clean report that means nothing. Hence the check before anything
  else. It happens on PG16 when a CREATEROLE user made the API roles itself (it gets them back
  without SET); Supabase's are granted to `postgres` by a superuser.
- The static audit fails when the session user has no USAGE on schema `auth`:
  `to_regclass('auth.users')` raises instead of returning NULL. Never the case on Supabase; not
  fixed yet.
- Inferring claims turned out to be what makes the probe useful on real apps: without
  `user_metadata.tenant_id`, the example's profiles policy turns every persona away, and the
  self-escalation on `profiles` stays hidden.

## Risks

- **False negatives** from personas the app would never produce (the spike). Mitigated by the
  tenancy model, by printing how personas were set up, and by not calling a clean probe proof.
- **Recipes failing** on rich schemas: references to reference data take stand-ins; what is
  still skipped is grouped by root cause with a hint, the coverage line warns, and
  `[probe.values]` fixes it.
- **Side effects** outside the transaction, and **locks** on a live database: trigger scan,
  short timeouts, local by default.
- **Fidelity**: the session user is `postgres`, not PostgREST's `authenticator`, so an invoker
  function that runs `RESET ROLE` would act as `postgres` during the probe but not through the
  API.

## Decisions

Taken 2026-10-05.

1. **`se-check audit --probe`, not a separate command.** One report, one exit code, one SARIF
   file; accepting, filtering and the GitHub Action work as they do. Rejected: `se-check probe`,
   which would duplicate the report pipeline and split CI into two steps.
2. **Non-local targets only with `--probe-remote`.** Even rolled back, the probe writes, takes
   locks and runs triggers on what may be production; local is where it belongs (the local
   stack, CI). Rejected: refusing remote targets outright, which leaves out staging databases
   people want to probe on purpose.
3. **MCP: a separate `probe_database` tool, enabled with `--probe` at server start, local
   targets only.** The agent that wrote the migration can check it on the local stack, but
   only if the team turned it on. Rejected: a `probe` parameter on `audit_database`, which is
   annotated read-only, and no MCP probing at all.
4. **Tenancy inferred from the catalog, `[probe]` in `se-check.toml` overrides.** The common
   Supabase layout (tenants, memberships, profiles) works with no setup, and coverage shows
   how each persona was provisioned so a wrong guess is visible. Rejected: mandatory
   configuration, a barrier for the most common case.
5. **Separate probe rules, linked to static findings with `confirms`.** Static and dynamic
   findings stay independent for acceptances and SARIF fingerprints, and the report can still
   say "confirmed by the probe". Rejected: upgrading static findings in place, which changes
   their identity depending on whether `--probe` ran, and has nowhere to put holes only the
   probe sees.

Taken 2026-10-19, after the field test of 2026-10-09:

6. **Coverage first, measured on targets.** The report opens with how many of the tables the
   probe could try it reached, and warns when that is not all of them; `--min-coverage` turns
   it into a CI gate. Tables in `[probe] skip_tables` are not targets: leaving one out is a
   decision the team reviews, like accepting a finding. Rejected: counting steps, which only
   exist for tables whose rows could be planned, so a broken schema would look covered.
7. **Stand-ins for missing reference rows, through transaction-local settings.** One plan code
   a CHECK rejected skipped 57 of 67 tables. Nullable references now take NULL, and required
   references to reference data a row the table already holds, whose key the database copies
   into `set_config(..., true)`: se-check never receives it. Rejected: reading the key into
   se-check, which breaks the rule against reading table contents; a subquery in each insert,
   which runs as the persona, whom RLS on the reference table may hide every row from.

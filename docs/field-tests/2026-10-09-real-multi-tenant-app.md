# Field test: se-check on a real multi-tenant app (2026-10-09)

First run of the static checks and the dynamic probe against a real application rather than
`examples/vulnerable-app`: what did not work, what can be improved, what can be added.

The report below is kept as written on 2026-10-09, except that the app is not named and its
table, column and label names are translated to English (in the app they are not English,
which matters for problem 7). What changed since is tracked here.

## Follow-up

| Problem (see [What did not work](#what-did-not-work)) | Status |
|---|---|
| 1. A probe that reached almost nothing looked like a clean result | **Fixed** 2026-10-19: coverage line before the findings, warning when incomplete, skips grouped by root cause, `--min-coverage` |
| 2. One failed reference row skipped 57 tables | **Fixed** 2026-10-19: a nullable reference is left NULL, a required reference to reference data takes an existing row |
| 3. Synthetic values ignore CHECK constraints | Open. The skip now says which constraint failed and to set a value in `[probe.values]` |
| 4. `[probe.values]` cannot say NULL | Open |
| 5. One synthetic row per table | Open |
| 6. Singleton tables collide | Open. The skip now suggests `[probe] skip_tables` for a duplicate key |
| 7. Privilege columns are recognized by English names only | Open: `privilege_columns` |
| 8. The persona's role comes from the column default, unreported | Open |
| 9. A self-escalation false positive on an informational column | Open |
| 10. Same severity for very different impact | Open |

Of the regression fixtures proposed at the end, the reference table referenced through a
nullable foreign key from the tenant table is in `examples/vulnerable-app` (`private.tiers`),
with a second one behind a required reference (`private.project_statuses`). The CHECK on their
codes stays unsatisfied on purpose, so that the stand-ins are exercised.

## Setup

- **Target**: a multi-tenant SaaS for field-service companies (shifts, time clock, inspections,
  inventory), built on Supabase. 67 tables in `public`, 60 of them tenant-scoped through
  `tenant_id`, access token hook that adds `tenant_id` and the user's role to the JWT, roles in an
  enum (`user_role`) plus a per-tenant custom role column.
- **Database**: a local copy only. The Supabase stack in Docker, rebuilt from scratch with
  `supabase db reset --local` (108 migrations, PostgreSQL 17.6). The hosted project was never
  touched, `--linked` was never used.
- **se-check**: 0.1.0 from the source tree (`uv run --project <se-check> se-check ...`), run
  from the app's folder. The config file lived outside the app's repo and was passed with
  `--config`.
- **Counting steps**: the text report gives statements and tables but not outcomes, so a small
  script called `plan_probe` and `execute` directly and counted the observations by outcome,
  scenario and persona.

## Results in numbers

| Run | Steps planned | Executed | Not executed | Tables probed | Blocked (filtered + denied) | Allowed |
|---|---|---|---|---|---|---|
| Static audit (7 checks) | — | 7 checks | 0 | — | — | 2 low findings |
| Probe, no config | 791 | **12** | **779** | **3 / 67** | 12 | 0 |
| Probe, first config | n/a | n/a | n/a | 53 / 67 | n/a | 2 high findings |
| Probe, full config, persona with the column default role | 761 | 761 | 0 | 64 / 67 | 758 | 3 |
| Same, persona as tenant owner | 761 | 761 | 0 | 64 / 67 | 758 | 3 |
| Same + `privilege_columns` (owner) | 767 | 767 | 0 | 64 / 67 | 759 | 8 |
| Same + `privilege_columns` (low-privilege member) | 767 | 767 | 0 | 64 / 67 | 764 | 3 |

No step ended `inconclusive` once the config was in place. Each full run took about 3 s
(896 statements). Two tables were never probed (see 5 and 6 below); a second run was needed to
cover a third one (see 4).

Coverage of the most complete run, by scenario:

| Scenario | Steps | Blocked | Allowed |
|---|---|---|---|
| anon | 247 | 247 | 0 |
| cross-tenant | 458 | 456 | 2 |
| tenant-hop | 55 | 54 | 1 |
| self-escalation | 7 (1 without `privilege_columns`) | 7 | 0 |
| cross-user | 0 (every table is tenant-scoped: not applicable) | — | — |

Personas that ran: `anon` (247 steps), `alice` (291), `outsider` (229). `mallory` did not run,
correctly: no policy reads `user_metadata`.

**Outcome for the app.** Two true findings, both confirmed by reading the policies: a
cross-tenant INSERT through a policy that checks the user but not the tenant, and a tenant hop on
a per-user table whose UPDATE policy lacks the tenant condition its INSERT policy has (low impact:
the row is read only by its owner). Both went to the app's own security register; details are
left out of this public file. One allowed self-escalation step was a false positive (see 8). A
finding from the 2026-10-05 run (access token hook callable via `/rpc`) had been fixed in the
meantime, and se-check no longer reported it.

## What worked

- Zero setup to start: run from the app folder, the local port came from `supabase/config.toml`.
- Speed: 0.8 s for the static audit, about 3 s for a probe of ~900 statements.
- Tenancy and claims inference: the tenant table, 60 tenant-scoped tables and the `tenant_id`
  claim (through the access token hook) were all found without configuration.
- Safety held: everything rolled back, no step inconclusive, nothing left in the database.
- `--config` outside the project, `[probe.values]` taking precedence over generated values,
  upserts that apply values to rows a signup trigger already created, `privilege_columns`.
- The low-privilege persona could not raise her own role or custom role, or move her profile to
  tenant B: the probe confirmed protections the app had added after a real incident.

## What did not work

### 1. A probe that reached almost nothing looked like a clean result

Without configuration the probe ran 12 of 791 planned steps on 3 of 67 tables. The summary line
was `2 findings: 2 low`, the same as a full run with nothing to report. The skip list was there,
but 64 lines long and after the findings.

### 2. One failed reference row skipped 57 tables

`tenants.plan_id` references `plans`. The synthetic plan failed its CHECK
constraint, so no tenant could be created, so every tenant-scoped table was skipped. But:

- `tenants.plan_id` is **nullable**: the tenant could have been created with NULL;
- `plans` already held 5 rows created by the migrations: any of them would have done.

### 3. Synthetic values ignore CHECK constraints

Four tables failed on constraints a generator could satisfy:

| Table | Constraint | Synthetic value | Would pass |
|---|---|---|---|
| `plans` | `code ~ '^[a-z_]+$'` | `se-check-<hex>` | `secheck_<letters>` |
| `monthly_reports` | `month ~ '^\d{4}-(0[1-9]\|1[0-2])$'` | `se-check-<hex>` | `2026-10` |
| `shift_templates` | `recurrence <> 'weekly' OR array_length(weekdays, 1) >= 1` | first enum label + NULL array | another label, or `{1}` |
| `discount_codes` | `(kind = 'referral' AND referrer_tenant IS NOT NULL) OR kind = 'ads' OR ...` | first enum label (`referral`) | `ads` |

Each failure skipped every table depending on it: `shift_templates` alone took 9 others with it,
among them the time clock and worked-hours tables, the most sensitive ones in the app.

### 4. `[probe.values]` cannot say NULL

`equipment_assignments` (equipment assigned to a worker or to a vehicle) has
`CHECK (num_nonnulls(worker_id, vehicle_id) = 1)`. Both parents had synthetic rows, so both
foreign keys were set. There is no way to ask for NULL in `[probe.values]`; the workaround was a
second run with the vehicles table in `skip_tables`.

### 5. One synthetic row per table

`travel_times` (travel times between two sites) has `CHECK (site_a_id <> site_b_id)`
and two foreign keys to the same table. With a single synthetic site per tenant it can never be
created. Never probed.

### 6. Singleton tables collide

`system_settings` has an integer primary key and one row (`id = 1`, set by a migration). The
synthetic insert hit `23505` on the primary key. Never probed (it is global reference data, so
little was lost, but the skip reason did not say so).

### 7. Privilege columns are recognized by English names only

The app's privilege columns (`role` and `employee_role` here) are not named in English.
Without `privilege_columns` the self-escalation scenario ran **1** step (the tenant move); with it, **7**. The class of bug this
scenario exists for (a user raising her own role) went untested by default, in exactly the app
where it had happened before.

### 8. The persona's role comes from the column default, and the report does not say which

`users.role` defaults to a low-privilege member. Good for self-escalation, weak for cross-tenant
checks: a hole that only a tenant owner can reach is masked by role checks. Setting
`[probe.values."public.users"] role = "owner"` works, but nothing in the report says which role
`alice` had, so a reader cannot tell what "no findings" covers.

### 9. A self-escalation false positive on an informational column

As owner, `alice` could set `invitations.role` (the role written on a pending invitation) to
`super_admin`. Nothing reads that column to grant privileges: the role is assigned when the
invitation is sent, and accepting it only marks the row accepted. Reported as escalation, it is a
data-quality issue at most. The probe cannot know what consumes a column, but it can say how sure
it is.

### 10. Same severity for very different impact

Both true findings were `high`. One lets a user put rows into another tenant's readable set; the
other moves a row only its owner can ever read. The probe already has the means to tell them
apart (see "Severity from a follow-up read" below).

## What can be improved

In rough order of value.

1. **Report coverage before findings, and make low coverage loud.**
   `Probe: 12 of 791 steps on 3 of 67 tables (tenant-scoped: 0 of 60). Most tables were skipped
   because public.plans could not be created: see below.` Group skips by root cause instead of
   listing 64 lines. In CI, an optional `--min-coverage 80` that fails the job.
2. **Fall back before skipping.** When a parent row cannot be created: use NULL if the foreign
   key is nullable; otherwise reuse an existing row of the parent table when the table is not
   tenant- or user-scoped (reference data). Only skip when neither works, and say which one was
   tried.
3. **Constraint-aware values.** Parse the simple CHECK shapes from `pg_get_constraintdef`:
   regular expressions with a small character class (`^[a-z_]+$`, a `YYYY-MM` pattern), `IN`
   lists, `BETWEEN` and comparisons, `num_nonnulls(...) = 1`, `a <> b`. On `23514` with an enum
   column involved, retry with the other labels. Each retry stays inside the savepoint, so it
   costs nothing but a statement.
4. **Detect privilege columns beyond names.** Candidates: enum columns whose labels match
   `_TOP_LABEL`; columns guarded by a BEFORE UPDATE trigger that compares `OLD.x` and `NEW.x`;
   columns read by the functions policies call (`is_manager()`, `has_permission()`). Keep the name
   list as one signal among others, and print which columns were tried.
5. **Say who the personas are.** One line per persona with the values that decide their
   privileges (`alice: users.role = member (column default)`), and a hint when the
   column is an enum with stronger labels.
6. **Concrete fix suggestions.** When another policy of the same table already ties rows to the
   tenant (the INSERT policy used `tenant_id = current_tenant_id()`), propose that expression for
   the UPDATE policy instead of `tenant_id in (select <function>())`.
7. **Lower confidence for self-escalation on rows that are not the user's identity.** An
   invitation the user created is "her own row" by `invited_by`, but not the row that defines
   her. Report it as `medium`, or as a separate scenario.

## What can be added

- **Per-step outcome counts in the report and in JSON**: planned and executed steps, and
  allowed / filtered / denied / inconclusive by scenario and persona. This field test needed a
  script for it; `ProbeCoverage` already holds most of the data.
- **NULL in `[probe.values]`**, for example `vehicle_id = { null = true }` (TOML has no null).
- **`[probe] persona_values`**: values applied to each persona's own rows only (role, custom role),
  instead of `[probe.values]`, which applies to every synthetic user, and a way to run the probe
  once per value (`role = ["owner", "member", "employee"]`).
- **Role matrix inside a tenant.** The most common bug class in this app is not cross-tenant but
  in-tenant: a worker reading colleagues' rows, an employee without a permission writing what only
  the office may write. With personas per role and a declared expectation
  (`[probe.expect] "public.time_entries" = { employee = "own rows" }`), the probe could check it
  too. Today only the app's pgTAP tests cover it.
- **Second synthetic row per table on demand**, or automatically when a CHECK compares two
  foreign keys to the same table.
- **Singleton detection** (CHECK on a constant key, or one row with a fixed id): skip with a clear
  reason, or probe the existing row read-only.
- **Severity from a follow-up read.** After a tenant hop succeeds, run a SELECT as `bob` (tenant B)
  on the moved row: if he can read it, the finding is a leak (`high`); if not, it is an integrity
  problem (`medium`).
- **`--probe-explain`**: print the plan (personas, claims, fixtures, steps per table) without
  running it, to debug a config before the probe touches anything.

## Regression fixtures to add to `examples/vulnerable-app`

Each item above can become a `SAFE` object, so that the golden test proves coverage instead of
assuming it:

- a reference table with `CHECK (code ~ '^[a-z_]+$')`, referenced through a nullable foreign key
  from the tenant table (items 2, 3);
- a tenant-scoped table with a month column in `YYYY-MM` format and one with an enum-dependent
  CHECK (item 3);
- an assignment table with `CHECK (num_nonnulls(a_id, b_id) = 1)` (item 4);
- a pair table with two foreign keys to the same table and `CHECK (a_id <> b_id)` (item 5);
- a singleton settings table (item 6);
- a `profiles` table whose privilege column has a non-English name, protected by a trigger, plus the
  same table without the trigger as `VULN` (item 7);
- an invitations table with a role column nothing consumes (item 9).

## Config used

Kept for reproducibility: these are the values the probe could not work out by itself.

```toml
[probe]
privilege_columns = ["role", "employee_role"]
skip_tables = [
  "public.system_settings",        # singleton (id = 1)
  "public.travel_times",           # CHECK (site_a_id <> site_b_id): needs two sites
  "public.equipment_assignments",  # num_nonnulls(worker_id, vehicle_id) = 1: second run without "public.vehicles"
]

[probe.values."public.plans"]
code = "probe_plan"               # CHECK (code ~ '^[a-z_]+$')

[probe.values."public.discount_codes"]
kind = "ads"                      # 'referral' requires referrer_tenant

[probe.values."public.monthly_reports"]
month = "2026-10"                 # YYYY-MM

[probe.values."public.shift_templates"]
weekdays = "{1,2,3,4,5}"          # weekly recurrence needs at least one day

[probe.values."public.users"]
role = "owner"                    # or leave it out for the column default (low-privilege member)
```

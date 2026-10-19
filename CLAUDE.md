# se-check

Security audit for Supabase/Postgres (RLS and multi-tenant isolation). CLI + MCP server.
Python ≥ 3.10, managed with uv. Public open-source project: code, comments and docs in English.

## Commands

- `uv sync` — install
- `uv run pytest` — tests. Database tests use `pgserver` (dev dependency, Python ≤ 3.12) or a
  disposable superuser server in `$SE_CHECK_TEST_DSN` (CI); without either they are skipped.
- `uv run ruff check . && uv run ruff format --check .` — lint and format (CI runs both)
- `uv run python scripts/playground.py` — example database without Docker, with a menu that
  runs se-check and explains the commands. The pgserver Postgres outlives its parent process,
  so the script stops it on q, Ctrl+C, SIGTERM and SIGHUP; keep it that way.
- `uv run se-check audit` — run from a Supabase project folder (local database, or `--linked`),
  or against `--dsn` / `$SE_CHECK_DSN`. Resolution order lives in `cli.resolve_target`.
- MCP mode must never prompt: stdin carries the protocol.

## Architecture

- `catalog.py` loads a snapshot (tables, grants, policies, functions) in one read-only
  transaction. `checks/` are pure functions `(Catalog, AuditConfig) -> Iterable[Finding]`:
  keep database access out of them.
- `audit.py` ties catalog and checks together and applies accepted findings; `cli.py` and
  `server.py` stay thin.
- `settings.py` reads `se-check.toml` (settings + `[[accept]]` entries, each with a mandatory
  reason). The CLI merges it with command-line options in `cli.build_plan`; the MCP server
  rebuilds the plan on every call, so edits apply without a restart.
- `connection.py` works out the target database (local stack from `supabase/config.toml`,
  `--linked` from `supabase/.temp/pooler-url`) and reads Auth hooks from `config.toml`.
- `locate.py` + `sarif.py`: SARIF output; results point at the latest migration that creates
  the object, relative to the git root.
- `probe/` is the dynamic probe (`audit --probe`, MCP `probe_database` with `mcp --probe`),
  designed in `docs/design/dynamic-probe.md`: `plan.py` (pure, from the catalog) → `execute.py`
  (the only module that writes: one transaction with `force_rollback=True`, a rolled-back
  savepoint per step) → `rules.py` (pure). `claims.py` infers the JWT claims personas need from
  the policies; without them every persona is turned away and the probe sees nothing. Probe
  rules are `Rule`s, not `Check`s; `rules.ALL_RULES` is the registry of both.
  `Catalog.support_tables` (other project schemas) is for the probe: checks use `Catalog.tables`.
  Coverage is measured on `ProbePlan.targets`; every `Skip` names its `cause`, and
  `probe.shown_skips` picks what the report shows. The report prints coverage before the
  findings: a probe that reached few tables must never pass for a clean one.
- `action.yml` (GitHub Action) runs `uvx --from $GITHUB_ACTION_PATH se-check`; inputs reach the
  script as environment variables only. Releases: `RELEASING.md`, `.github/workflows/release.yml`.
- The MCP SDK is v2: `mcp.server.mcpserver.MCPServer` (FastMCP no longer exists). Raise
  `ToolError` for failures the model should read; anything else is reported as a crash.

## Docs

- `README.md` is the user documentation. Its sample output is real output on
  `examples/vulnerable-app`: regenerate it when findings or wording change.
- `CHANGELOG.md`: add user-visible changes under `## [Unreleased]`.
- `docs/design/`: designs, with the Postgres behavior they rely on and dated decisions.
  `docs/field-tests/`: runs on real applications, kept as written; their Follow-up table tracks
  what changed since. Keep details of those applications out: this repository is public.
- `examples/vulnerable-app/README.md` describes the example's objects; the SQL tags are the
  source of truth.

## Rules

- Never read table contents, and keep findings to metadata. Never take the DSN as a tool argument.
  The probe addresses only rows it created, by the keys it generated, and keeps SQLSTATEs, never
  error messages (they can carry values). It never commits, and runs on non-local targets only
  with `--probe-remote`. A synthetic row may point at an existing row of reference data, but
  only through a transaction-local setting the database fills (`execute._find_existing`): the
  value never reaches se-check.
- Every check needs unit tests (positive and negative cases) in `tests/test_checks*.py` and
  `VULN`/`SAFE` objects in `examples/vulnerable-app`, listed in `EXPECTED` in
  `tests/test_integration.py` (`EXPECTED_PROBE` for probe rules). That golden test catches false
  positives too. Other tests derive counts from them instead of hard-coding them.
- The MCP server must not accept findings by itself: accepting is the team's decision.
- Verify Postgres semantics on a real server before encoding them. Established so far: an UPDATE
  policy without WITH CHECK reuses USING for new rows; a policy with no expression denies; an
  UPDATE whose WHERE reads columns also checks the new row against SELECT policies. For the
  probe: RLS applies after `SET LOCAL ROLE` even in a superuser session; rolling back a savepoint
  undoes `SET LOCAL`; INSERT checks RLS before unique constraints; WITH CHECK and a missing grant
  both raise 42501; a `set_config(..., true)` made before a savepoint survives rolling it back;
  foreign key checks ignore RLS on the referenced table.
- Policy expressions are compared in their deparsed form (`pg_get_expr`): get the exact text
  from Postgres instead of guessing it.
- Don't `create extension vector` in tests: the pgvector bundled with pgserver crashes the server.
- Test fixtures connect as a superuser, which Supabase never hands out: probe behavior must also
  hold under `supabase_role_dsn` (NOSUPERUSER BYPASSRLS, member of the API roles).
- `ruff format --check` formats Python blocks inside Markdown too.

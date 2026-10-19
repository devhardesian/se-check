# Changelog

Notable changes to se-check. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow
[Semantic Versioning](https://semver.org/).

## [Unreleased]

The first release, 0.1.0.

### Static audit

- Seven checks: `rls-disabled`, `permissive-policy`, `user-metadata-auth`, `auth-hook-exposed`,
  `signup-trigger-metadata`, `definer-no-caller-check` and `definer-search-path`. Each finding
  explains the hole and suggests a fix.
- Targets: the local Supabase stack, found through `supabase/config.toml`; the hosted project
  linked with `supabase link` (`--linked`); any Postgres (`--dsn`, `$SE_CHECK_DSN`).
- Reports as text, JSON or SARIF. SARIF results point at the migration that created each
  object.
- `se-check.toml` for settings, and for accepted findings with a mandatory reason
  (`se-check accept`).

### Dynamic probe

- `se-check audit --probe` acts as `anon`, as members of two tenants, as a user of no tenant and
  as a user who forged her `user_metadata`, on synthetic rows, inside a transaction it always
  rolls back. Six rules: anon access, cross-tenant and cross-user reads and writes, and
  self-escalation.
- Personas built from the schema: the tenant table and memberships from foreign keys, the JWT
  claims the policies read, and the custom access token hook.
- Coverage before the findings: how many of the tables it could try the probe reached, with a
  warning when that is not all of them, and the tables it missed grouped by the row that was
  missing. `--min-coverage` fails the run below a threshold.
- Stand-ins for missing reference rows: a nullable reference is left NULL, a required one
  takes a row the table already holds, whose key se-check never sees.
- Local databases only, unless `--probe-remote` is given.

### Integrations

- MCP server (`se-check mcp`) with `audit_database` and `list_checks`, and `probe_database` with
  `--probe` on a local database.
- GitHub Action with SARIF annotations, and `probe` and `min-coverage` inputs.
- A deliberately vulnerable example app, and a playground that runs it without Docker.

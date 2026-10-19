"""Command line interface: `se-check audit`, `accept`, `checks` and `mcp`."""

from __future__ import annotations

import argparse
import getpass
import json
import os
import sys
import textwrap
from dataclasses import replace
from pathlib import Path

from se_check import __version__
from se_check.audit import AuditError, AuditPlan, run_audit
from se_check.checks import ALL_CHECKS
from se_check.config import DEFAULT_API_ROLES, DEFAULT_TENANT_COLUMNS, AuditConfig
from se_check.connection import (
    Target,
    TargetError,
    access_token_hook,
    auth_hooks,
    dsn_target,
    find_supabase_project,
    has_password,
    has_placeholder,
    linked_pooler_url,
    linked_target,
    local_target,
    with_password,
)
from se_check.models import Severity
from se_check.probe import PROBE_RULES
from se_check.rules import ALL_RULES, PROBE_RULE_IDS
from se_check.settings import (
    SETTINGS_FILE,
    Acceptance,
    ProjectSettings,
    SettingsError,
    append_acceptance,
    load_settings,
)

DSN_ENV = "SE_CHECK_DSN"
PASSWORD_ENV = "SUPABASE_DB_PASSWORD"  # the same variable the Supabase CLI reads

_SEVERITY_NAMES = [s.label for s in Severity]


def known_check_ids() -> set[str]:
    return {rule.id for rule in ALL_RULES}


class _UsageError(Exception):
    pass


def _percent(text: str) -> float:
    try:
        value = float(text)
    except ValueError:
        value = -1.0
    if not 0 <= value <= 100:
        raise argparse.ArgumentTypeError(f"expected a percentage from 0 to 100, got {text!r}")
    return value


# --- arguments --------------------------------------------------------------------------------


def _add_project_options(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--project",
        metavar="PATH",
        help="Supabase project folder, the one with supabase/config.toml (default: the "
        "current folder or the closest one above it)",
    )
    parser.add_argument(
        "--config",
        metavar="FILE",
        help=f"settings file (default: {SETTINGS_FILE} in the project folder)",
    )


def _add_database_options(parser: argparse.ArgumentParser) -> None:
    _add_project_options(parser)
    parser.add_argument(
        "--linked",
        action="store_true",
        help="audit the hosted project this folder is linked to with `supabase link`, instead "
        f"of the local database (asks for the database password, or reads ${PASSWORD_ENV})",
    )
    parser.add_argument(
        "--dsn",
        help=f"connection string of any Postgres database (or set ${DSN_ENV}). Prefer the "
        "variable: command-line arguments end up in your shell history.",
    )
    parser.add_argument(
        "--schema",
        dest="schemas",
        action="append",
        metavar="NAME",
        help="schema exposed through the Data API (repeatable; default: public)",
    )
    parser.add_argument(
        "--api-role",
        dest="api_roles",
        action="append",
        metavar="ROLE",
        help="role API requests run as (repeatable; default: anon, authenticated)",
    )
    parser.add_argument(
        "--tenant-column",
        dest="tenant_columns",
        action="append",
        metavar="NAME",
        help="extra column that marks a table as tenant-scoped (repeatable; tenant_id, org_id, "
        "team_id, workspace_id, ... are built in)",
    )
    parser.add_argument(
        "--guard",
        dest="guards",
        action="append",
        metavar="FUNCTION",
        help="function that checks the caller in a way se-check cannot see, e.g. one written in "
        "C (repeatable). Helpers that read auth.uid() or auth.jwt() are recognized by themselves.",
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="se-check",
        description="Find Row Level Security and multi-tenant isolation holes in "
        "Supabase/Postgres.",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    commands = parser.add_subparsers(dest="command", required=True)

    audit = commands.add_parser("audit", help="audit a database and print the findings")
    _add_database_options(audit)
    audit.add_argument(
        "--check",
        dest="checks",
        action="append",
        choices=[rule.id for rule in ALL_RULES],
        metavar="ID",
        help="run only this check (repeatable; see `se-check checks`)",
    )
    audit.add_argument(
        "--probe",
        action="store_true",
        help="also run the dynamic probe: act as anon and as users of two tenants on synthetic "
        "rows, inside a transaction that is always rolled back. Local databases only, unless "
        "--probe-remote is given.",
    )
    audit.add_argument(
        "--probe-remote",
        action="store_true",
        help="let --probe run on a database that is not on this machine",
    )
    audit.add_argument(
        "--min-coverage",
        type=_percent,
        metavar="PERCENT",
        help="with --probe: exit with status 1 when the probe reaches less than this share of "
        "the tables it could try (tables in [probe] skip_tables don't count)",
    )
    audit.add_argument(
        "--min-severity",
        choices=_SEVERITY_NAMES,
        default="low",
        help="hide findings below this severity (default: low)",
    )
    audit.add_argument(
        "--fail-on",
        choices=[*_SEVERITY_NAMES, "never"],
        default="high",
        help="exit with status 1 when a finding is at least this severe, whatever "
        "--min-severity hides; accepted findings never count (default: high)",
    )
    audit.add_argument("--format", choices=("text", "json", "sarif"), default="text")
    audit.add_argument(
        "--sarif",
        metavar="FILE",
        help="also write the findings as SARIF to FILE, for GitHub code scanning",
    )
    audit.add_argument("--no-color", action="store_true", help="plain text output")

    accept = commands.add_parser(
        "accept",
        help=f"record a finding as fine on purpose, with the reason, in {SETTINGS_FILE}",
    )
    accept.add_argument(
        "check", choices=[rule.id for rule in ALL_RULES], metavar="CHECK", help="check id"
    )
    accept.add_argument("object", help="the object as the report shows it, e.g. public.plans")
    accept.add_argument("--reason", required=True, help="why this finding is fine")
    accept.add_argument(
        "--policy", help="accept only this policy of the table (for policy findings)"
    )
    _add_project_options(accept)

    commands.add_parser("checks", help="list the available checks")

    mcp = commands.add_parser("mcp", help="run the MCP server over stdio")
    _add_database_options(mcp)
    mcp.add_argument(
        "--probe",
        action="store_true",
        help="also offer probe_database, which runs the dynamic probe (local databases only)",
    )
    return parser


# --- settings ---------------------------------------------------------------------------------


def _folder(args: argparse.Namespace) -> Path:
    return Path(args.project) if args.project else Path.cwd()


def settings_path(args: argparse.Namespace) -> Path:
    """--config, or se-check.toml in the Supabase project folder (else in this folder)."""
    if args.config:
        return Path(args.config)
    folder = _folder(args)
    return (find_supabase_project(folder) or folder) / SETTINGS_FILE


def _load_settings(args: argparse.Namespace) -> ProjectSettings:
    path = settings_path(args)
    if not args.config and not path.is_file():
        return ProjectSettings()
    return load_settings(path, known_check_ids())


def build_plan(args: argparse.Namespace) -> AuditPlan:
    """Settings from se-check.toml, with command-line options on top."""
    settings = _load_settings(args)
    project = find_supabase_project(_folder(args))
    config = AuditConfig(
        auth_hooks=auth_hooks(project) if project else (),
        access_token_hook=access_token_hook(project) if project else None,
        schemas=tuple(args.schemas or settings.schemas or ("public",)),
        api_roles=tuple(args.api_roles or settings.api_roles or DEFAULT_API_ROLES),
        tenant_columns=tuple(
            dict.fromkeys(
                (*DEFAULT_TENANT_COLUMNS, *settings.tenant_columns, *(args.tenant_columns or ()))
            )
        ),
        guard_functions=tuple(dict.fromkeys((*settings.guards, *(args.guards or ())))),
    )
    return AuditPlan(
        config=config,
        accepted=settings.accepted,
        settings_file=settings.path,
        probe=settings.probe,
    )


# --- which database ---------------------------------------------------------------------------


def resolve_target(args: argparse.Namespace, *, interactive: bool) -> Target:
    """Which database to audit.

    In order: --dsn, --linked, $SE_CHECK_DSN, the local database of the Supabase project in
    this folder, and, when someone is at the keyboard, a connection string pasted at the prompt.
    """
    folder = _folder(args)
    if args.dsn:
        return _fill_placeholder(dsn_target(args.dsn, "the database given with --dsn"), interactive)
    if args.linked:
        project = find_supabase_project(folder)
        if project is None:
            raise _UsageError(
                f"--linked needs a Supabase project, but there is no supabase/config.toml in "
                f"{folder} or above it: run se-check from the project folder, or pass --project."
            )
        linked_pooler_url(project)  # not linked: say so before asking for a password
        return linked_target(project, os.environ.get(PASSWORD_ENV) or _ask_password(interactive))
    if os.environ.get(DSN_ENV):
        target = dsn_target(os.environ[DSN_ENV], f"the database in ${DSN_ENV}")
        return _fill_placeholder(target, interactive)
    project = find_supabase_project(folder)
    if project is not None:
        return local_target(project)
    if interactive:
        return _ask_connection_string()
    raise _UsageError(
        "no database to audit. Run se-check in a Supabase project folder (it finds the local "
        "database by itself, or the hosted one with --linked), or pass a connection string "
        "with --dsn."
    )


def _fill_placeholder(target: Target, interactive: bool) -> Target:
    if not has_placeholder(target.dsn):
        return target
    return replace(target, dsn=with_password(target.dsn, _ask_password(interactive)))


def _ask_password(interactive: bool) -> str:
    if not interactive:
        raise _UsageError(f"the database password is missing: set {PASSWORD_ENV}")
    try:
        password = getpass.getpass("Database password (it won't show while you type): ")
    except EOFError:
        password = ""
    if not password:
        raise _UsageError("no password given")
    return password


def _ask_connection_string() -> Target:
    # Prompts go to stderr, so `--format json` output stays clean.
    print(
        "No Supabase project in this folder and no database configured.\n"
        "Paste a connection string (on Supabase: Dashboard → Connect → Session pooler),\n"
        "or press Enter to cancel.",
        file=sys.stderr,
    )
    print("> ", end="", file=sys.stderr, flush=True)
    dsn = sys.stdin.readline().strip()
    if not dsn:
        raise _UsageError("no database to audit")
    target = dsn_target(dsn, "the database you pasted")
    if has_placeholder(dsn) or not has_password(dsn):
        target = replace(target, dsn=with_password(dsn, _ask_password(True)))
    return target


def _with_hint(message: str, hint: str) -> str:
    return f"{message}\nhint: {hint}" if hint else message


# --- commands ---------------------------------------------------------------------------------


def _use_color(args: argparse.Namespace) -> bool:
    return not args.no_color and "NO_COLOR" not in os.environ and sys.stdout.isatty()


_REMOTE_PROBE = (
    "--probe writes to the database, inside a transaction it always rolls back, and fires its "
    "triggers: it is meant for the local stack, CI or a disposable copy. {target} is not on "
    "this machine; add --probe-remote to probe it anyway."
)


_MCP_REMOTE_PROBE = (
    "se-check mcp --probe only runs on a local database (the local stack, a loopback address): "
    "the agent decides when to call it. {target} is not on this machine."
)


def _capitalized(text: str) -> str:
    return text[:1].upper() + text[1:]


def _check_probe_options(args: argparse.Namespace) -> None:
    if args.probe_remote and not args.probe:
        raise _UsageError("--probe-remote only makes sense together with --probe")
    if args.min_coverage is not None and not args.probe:
        raise _UsageError("--min-coverage only makes sense together with --probe")
    probe_rules = [rule_id for rule_id in args.checks or () if rule_id in PROBE_RULE_IDS]
    if probe_rules and not args.probe:
        raise _UsageError(f"{', '.join(probe_rules)} come(s) from the dynamic probe: add --probe")
    # Say no before asking for the password of a database we would refuse anyway.
    if args.probe and args.linked and not args.probe_remote:
        raise _UsageError(_REMOTE_PROBE.format(target="The linked project"))


def _audit(args: argparse.Namespace) -> int:
    from se_check.report import render_text
    from se_check.sarif import to_sarif

    plan = build_plan(args)  # a broken se-check.toml should stop us before any prompt
    _check_probe_options(args)
    target = resolve_target(args, interactive=sys.stdin.isatty())
    if args.probe and not target.local and not args.probe_remote:
        raise _UsageError(_REMOTE_PROBE.format(target=_capitalized(target.label)))
    print(f"Auditing {target.label}...", file=sys.stderr, flush=True)
    if args.probe:
        print(
            "Probing it as anon and as users of two tenants, in a transaction that is rolled "
            "back...",
            file=sys.stderr,
            flush=True,
        )
    try:
        report = run_audit(target.dsn, plan, args.checks, probe=args.probe)
    except AuditError as exc:
        raise AuditError(_with_hint(str(exc), target.hint)) from exc
    shown = report.filtered(Severity.parse(args.min_severity))
    project = find_supabase_project(_folder(args))
    if args.format == "json":
        print(json.dumps(shown.to_dict(), indent=2))
    elif args.format == "sarif":
        print(json.dumps(to_sarif(shown, project=project), indent=2))
    else:
        print(render_text(shown, color=_use_color(args)))
    if args.sarif:
        Path(args.sarif).write_text(json.dumps(to_sarif(shown, project=project), indent=2) + "\n")
        print(f"SARIF written to {args.sarif}", file=sys.stderr)
    code = 0
    if args.fail_on != "never":
        threshold = Severity.parse(args.fail_on)
        code = 1 if any(f.severity >= threshold for f in report.findings) else 0
    coverage = report.probe
    if args.min_coverage is not None and coverage and coverage.ratio * 100 < args.min_coverage:
        reached = (
            "did not run"
            if coverage.blocked
            else f"reached {len(coverage.reached)} of {len(coverage.targets)} tables"
        )
        print(
            f"se-check: the probe {reached} ({coverage.ratio:.0%}), less than --min-coverage "
            f"{args.min_coverage:g}%",
            file=sys.stderr,
        )
        code = 1
    return code


def _accept(args: argparse.Namespace) -> int:
    if not args.reason.strip():
        raise _UsageError("the reason can't be empty: write down why this finding is fine")
    path = settings_path(args)
    acceptance = Acceptance(
        check=args.check, object=args.object, reason=args.reason.strip(), policy=args.policy
    )
    if path.is_file():  # refuse to append to a file that is already broken
        existing = load_settings(path, known_check_ids()).accepted
        key = (acceptance.check, acceptance.object, acceptance.policy)
        if any((a.check, a.object, a.policy) == key for a in existing):
            print(f"{acceptance.describe()} is already accepted in {path}")
            return 0
    append_acceptance(path, acceptance)
    print(f"Accepted {acceptance.describe()} in {path}")
    return 0


def _list_checks() -> int:
    for heading, rules in (
        ("Static checks (se-check audit):", ALL_CHECKS),
        ("Dynamic probe (se-check audit --probe):", PROBE_RULES),
    ):
        if rules is PROBE_RULES:
            print()
        print(heading)
        for rule in rules:
            print(f"\n{rule.id}\n  {rule.title}")
            print(
                textwrap.fill(
                    rule.description, width=88, initial_indent="  ", subsequent_indent="  "
                )
            )
    return 0


def _mcp(args: argparse.Namespace) -> int:
    from se_check.server import build_server  # the MCP SDK is only needed here

    # stdin carries the MCP protocol: never prompt here.
    if args.probe and args.linked:
        raise _UsageError(_MCP_REMOTE_PROBE.format(target="The linked project"))
    target = resolve_target(args, interactive=False)
    if args.probe and not target.local:
        raise _UsageError(_MCP_REMOTE_PROBE.format(target=_capitalized(target.label)))
    print(f"se-check MCP server: auditing {target.label}", file=sys.stderr, flush=True)
    # se-check.toml is read again on every call, so edits apply without a restart.
    server = build_server(target.dsn, lambda: build_plan(args), hint=target.hint, probe=args.probe)
    server.run()  # stdout is the protocol
    return 0


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    commands = {"audit": _audit, "accept": _accept, "mcp": _mcp}
    try:
        if args.command == "checks":
            return _list_checks()
        return commands[args.command](args)
    except (_UsageError, TargetError, SettingsError, AuditError) as exc:
        print(f"se-check: error: {exc}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        print(file=sys.stderr)
        return 130

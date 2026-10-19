"""Run an audit: load the catalog, run the checks, collect the findings in a report."""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Any

import psycopg

from se_check import __version__
from se_check.catalog import Catalog, load_catalog
from se_check.checks import run_checks
from se_check.config import AuditConfig, ProbeConfig
from se_check.db import connect
from se_check.models import Finding, Severity
from se_check.probe import ProbeResult, link_confirmations, run_probe
from se_check.probe.model import ProbeCoverage
from se_check.rules import select_rules
from se_check.settings import Acceptance


class AuditError(Exception):
    """The audit could not run: connection refused, missing privileges, timeout..."""


@dataclass(frozen=True)
class AuditPlan:
    """What to check and which findings were accepted on purpose (from se-check.toml)."""

    config: AuditConfig = field(default_factory=AuditConfig)
    accepted: tuple[Acceptance, ...] = ()
    settings_file: Path | None = None
    probe: ProbeConfig = field(default_factory=ProbeConfig)


@dataclass(frozen=True)
class AcceptedFinding:
    finding: Finding
    reason: str


@dataclass(frozen=True)
class AuditReport:
    server_version: str
    schemas: tuple[str, ...]
    api_roles: tuple[str, ...]
    missing_api_roles: tuple[str, ...]
    """Configured API roles that don't exist: usually a sign this is not a Supabase database."""
    findings: tuple[Finding, ...]
    hidden: int = 0
    """Findings left out by `filtered`, so a reader knows the list is not everything."""
    accepted: tuple[AcceptedFinding, ...] = ()
    unused_acceptances: tuple[Acceptance, ...] = ()
    """Accepted findings that no longer occur: the entries can go."""
    settings_file: Path | None = None
    probe: ProbeCoverage | None = None
    """What the dynamic probe tried, when it ran."""

    def counts(self) -> dict[str, int]:
        return {
            severity.label: sum(1 for f in self.findings if f.severity == severity)
            for severity in sorted(Severity, reverse=True)
        }

    def filtered(self, min_severity: Severity) -> AuditReport:
        kept = tuple(f for f in self.findings if f.severity >= min_severity)
        return replace(self, findings=kept, hidden=self.hidden + len(self.findings) - len(kept))

    def to_dict(self) -> dict[str, Any]:
        return {
            "tool": "se-check",
            "version": __version__,
            "server_version": self.server_version,
            "schemas": list(self.schemas),
            "api_roles": list(self.api_roles),
            "missing_api_roles": list(self.missing_api_roles),
            "summary": self.counts(),
            "hidden_below_min_severity": self.hidden,
            "findings": [finding.to_dict() for finding in self.findings],
            "settings_file": str(self.settings_file) if self.settings_file else None,
            "accepted": [
                {**item.finding.to_dict(), "reason": item.reason} for item in self.accepted
            ],
            "unused_acceptances": [
                {"check": a.check, "object": a.object, "policy": a.policy}
                for a in self.unused_acceptances
            ],
            "probe": self.probe.to_dict() if self.probe else None,
        }


def apply_acceptances(
    findings: Iterable[Finding], accepted: Iterable[Acceptance], checks_run: Iterable[str]
) -> tuple[tuple[Finding, ...], tuple[AcceptedFinding, ...], tuple[Acceptance, ...]]:
    """Split findings into open and accepted; also return the entries that matched nothing."""
    accepted = tuple(accepted)
    open_findings: list[Finding] = []
    matched: list[AcceptedFinding] = []
    used: set[Acceptance] = set()
    for finding in findings:
        acceptance = next((a for a in accepted if a.matches(finding)), None)
        if acceptance is None:
            open_findings.append(finding)
        else:
            matched.append(AcceptedFinding(finding, acceptance.reason))
            used.add(acceptance)
    # Only entries for checks that ran can be judged unused.
    ran = set(checks_run)
    unused = tuple(a for a in accepted if a not in used and a.check in ran)
    return tuple(open_findings), tuple(matched), unused


def audit_catalog(
    catalog: Catalog,
    plan: AuditPlan | AuditConfig,
    check_ids: Iterable[str] | None = None,
    probe: ProbeResult | None = None,
) -> AuditReport:
    """`probe` holds the dynamic probe's results, when it ran."""
    if isinstance(plan, AuditConfig):
        plan = AuditPlan(plan)
    config = plan.config
    checks, probe_rules = select_rules(check_ids, probe=probe is not None)
    findings = run_checks(catalog, config, [c.id for c in checks]) if checks else []
    if probe is not None:
        wanted = {rule.id for rule in probe_rules}
        findings += link_confirmations((f for f in probe.findings if f.check in wanted), findings)
        findings.sort(key=lambda f: (-f.severity, f.check, f.object))
    checks_run = [rule.id for rule in (*checks, *probe_rules)]
    findings, accepted, unused = apply_acceptances(findings, plan.accepted, checks_run)
    return AuditReport(
        server_version=catalog.server_version,
        schemas=config.schemas,
        api_roles=catalog.api_roles,
        missing_api_roles=tuple(r for r in config.api_roles if r not in catalog.api_roles),
        findings=findings,
        accepted=accepted,
        unused_acceptances=unused,
        settings_file=plan.settings_file,
        probe=probe.coverage if probe else None,
    )


def run_audit(
    dsn: str,
    plan: AuditPlan | AuditConfig,
    check_ids: Iterable[str] | None = None,
    *,
    probe: bool = False,
) -> AuditReport:
    """`probe` also runs the dynamic probe, which writes inside a transaction it rolls back:
    the caller decides whether the target may be probed."""
    if isinstance(plan, AuditConfig):
        plan = AuditPlan(plan)
    check_ids = list(check_ids) if check_ids else None
    select_rules(check_ids, probe=probe)  # reject unknown ids before connecting
    probe_result = None
    try:
        with connect(dsn) as conn:
            catalog = load_catalog(conn, plan.config)
        if probe:
            probe_result = run_probe(dsn, catalog, plan.config, plan.probe)
    except psycopg.Error as exc:
        raise AuditError(f"database error: {describe_db_error(exc)}") from exc
    return audit_catalog(catalog, plan, check_ids, probe_result)


def describe_db_error(exc: psycopg.Error) -> str:
    text = str(exc).strip()
    return text.splitlines()[0] if text else type(exc).__name__

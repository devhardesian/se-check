"""The dynamic probe: act as anon and as users of two tenants, inside a rolled-back transaction.

The static checks read definitions; the probe asks Postgres. It creates synthetic users,
tenants and rows, then tries to read and change tenant B's rows as `anon`, as a member of
tenant A and as a user of no tenant. Everything is rolled back, only rows the probe created
are addressed, and findings carry metadata only. See docs/design/dynamic-probe.md.

    plan_probe (pure) -> execute (the database) -> interpret (pure)
"""

from __future__ import annotations

import random
from contextlib import closing
from dataclasses import dataclass

from se_check.catalog import Catalog
from se_check.config import AuditConfig, ProbeConfig
from se_check.db import connect_for_probe
from se_check.models import Finding
from se_check.probe.execute import Execution, execute
from se_check.probe.model import Outcome, ProbeCoverage, ProbePlan, Skip
from se_check.probe.plan import plan_probe
from se_check.probe.rules import PROBE_RULES, interpret, link_confirmations


@dataclass(frozen=True)
class ProbeResult:
    findings: tuple[Finding, ...]
    coverage: ProbeCoverage


def run_probe(
    dsn: str,
    catalog: Catalog,
    config: AuditConfig,
    probe: ProbeConfig | None = None,
    *,
    rng: random.Random | None = None,
) -> ProbeResult:
    """Raises psycopg.Error when the database cannot be reached."""
    plan = plan_probe(catalog, config, probe, rng)
    known = {t.qualified_name for t in (*catalog.tables, *catalog.support_tables)}
    if plan.blocked:
        return ProbeResult((), _coverage(plan, known, Execution(blocked=plan.blocked)))

    # closing(), not the connection's own context manager: that one commits on the way out.
    with closing(connect_for_probe(dsn)) as conn:
        execution = execute(conn, plan)
    findings = tuple(interpret(catalog, plan, execution.observations))
    return ProbeResult(findings, _coverage(plan, known, execution))


def _coverage(plan: ProbePlan, known: set[str], execution: Execution) -> ProbeCoverage:
    observations = execution.observations
    inconclusive = tuple(o for o in observations if o.outcome is Outcome.INCONCLUSIVE)
    conclusive = {o.step.table_name for o in observations if o.outcome is not Outcome.INCONCLUSIVE}
    tenancy = plan.tenancy
    return ProbeCoverage(
        tenancy=tenancy.describe(),
        personas=tuple(execution.personas),
        probed=tuple(sorted(conclusive)),
        skipped=shown_skips(
            (*plan.skipped, *execution.skipped),
            plan.targets,
            known,
            {stand_in.parent for stand_in in execution.stand_ins},
        ),
        inconclusive=inconclusive,
        statements=execution.statements,
        blocked=execution.blocked,
        claims=tuple(execution.claims),
        targets=plan.targets,
        scoped_targets=tuple(
            t for t in plan.targets if t in tenancy.scoped and t != tenancy.tenant_table
        ),
        left_out=plan.left_out,
        planned_steps=len(plan.steps),
        steps_run=len(observations),
        stand_ins=tuple(execution.stand_ins),
    )


def shown_skips(
    skips: tuple[Skip, ...],
    targets: tuple[str, ...],
    known: set[str],
    parents: set[str] = frozenset(),
) -> tuple[Skip, ...]:
    """The skips worth reporting: those of the tables the probe meant to try, the skips that
    caused them (in any schema), the tables whose missing rows other rows took stand-ins for,
    and the setup steps that failed (users, membership, hook)."""
    first: dict[str, Skip] = {}
    for skip in skips:
        first.setdefault(skip.table, skip)
    shown: set[str] = set()
    for skip in skips:
        if skip.table not in known:
            shown.add(skip.table)
        elif skip.table in targets or skip.table in parents:
            table: str | None = skip.table
            while table in first and table not in shown:
                shown.add(table)
                table = first[table].cause
    return tuple(skip for skip in skips if skip.table in shown)


__all__ = ["PROBE_RULES", "ProbeResult", "link_confirmations", "run_probe"]

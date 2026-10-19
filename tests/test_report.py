from __future__ import annotations

from dataclasses import replace

from se_check.audit import AuditReport
from se_check.models import Finding, Severity
from se_check.probe.model import Observation, Outcome, ProbeCoverage, Skip, StandIn, Step
from se_check.report import render_text

LONG_SQL = (
    "revoke execute on function public.a_function_with_a_rather_long_name(p_first uuid, "
    "p_second text) from public, anon, authenticated;"
)


def _report(*findings: Finding, missing=()) -> AuditReport:
    return AuditReport(
        server_version="16.2",
        schemas=("public",),
        api_roles=("anon", "authenticated"),
        missing_api_roles=missing,
        findings=findings,
    )


def _finding(remediation: str) -> Finding:
    return Finding(
        check="definer-no-caller-check",
        severity=Severity.HIGH,
        object="public.f()",
        title="title",
        detail="detail",
        remediation=remediation,
    )


def test_sql_statements_are_never_wrapped():
    prose = "Check the caller first, " * 8
    lines = render_text(_report(_finding(f"{prose}\n{LONG_SQL}\n-- {prose}"))).splitlines()
    assert any(line.strip() == LONG_SQL for line in lines)
    assert all(len(line) <= 92 for line in lines if LONG_SQL not in line)


def test_plain_output_has_no_escape_codes():
    out = render_text(_report(_finding("fix it")), color=False)
    assert "\033[" not in out
    assert "1 findings: 1 high" in out


def test_color_output_paints_severity():
    assert "\033[31mHIGH" in render_text(_report(_finding("fix it")), color=True)


def test_empty_report_and_missing_roles():
    out = render_text(_report(missing=("web_user",)))
    assert "No findings." in out
    assert "web_user" in out


def _coverage(**fields) -> ProbeCoverage:
    defaults = {
        "tenancy": "tenants in public.tenants, 3 tenant-scoped tables",
        "personas": (),
        "probed": (),
        "skipped": (),
        "inconclusive": (),
        "statements": 42,
    }
    return ProbeCoverage(**{**defaults, **fields})


def _flat(text: str) -> str:
    return " ".join(text.split())  # undo the wrapping to the terminal


def test_probe_coverage_is_part_of_the_report():
    step = Step("alice", "public", "orders", "UPDATE", "B", target="public.orders@B")
    coverage = _coverage(
        probed=("public.orders", "public.tenants"),
        inconclusive=(Observation(step, Outcome.INCONCLUSIVE, "23514"),),
        claims=("app_metadata.tenant_id (read by your policies)",),
        targets=("public.orders", "public.tenants"),
        planned_steps=9,
        steps_run=9,
    )
    text = render_text(replace(_report(), probe=coverage))
    assert "Personas' JWT claims: app_metadata.tenant_id (read by your policies)." in text
    assert (
        "Probe: 42 statements, all rolled back. Tenants in public.tenants, "
        "3 tenant-scoped tables." in _flat(text)
    )
    assert "  inconclusive public.orders: UPDATE as alice failed with 23514" in text
    head = text.split("No findings.")[0].splitlines()[1]
    assert head.startswith("Probe: reached all 2 tables it could try, with 9 steps")
    assert "warning" not in text


def test_incomplete_probe_warns_before_and_after_the_findings():
    targets = tuple(f"public.t{i}" for i in range(10))
    needs_plans = "needs a row of public.plans, which could not be created"
    coverage = _coverage(
        probed=targets[:3],
        skipped=(
            *(Skip(t, needs_plans, "public.plans") for t in targets[3:]),
            Skip("public.plans", "could not insert a synthetic row (23514)"),
        ),
        targets=targets,
        scoped_targets=targets[1:],
        planned_steps=100,
        steps_run=12,
    )
    finding = _finding("fix it")
    text = render_text(replace(_report(finding), probe=coverage))
    before, after = text.split(finding.title)
    assert (
        "warning: the probe reached 3 of 10 tables (2 of 9 tenant-scoped), with 12 of 100 "
        "planned steps: no probe finding on the other 7 says nothing about them. 7 of them "
        "because public.plans got no synthetic row." in _flat(before)
    )
    assert (
        "warning: the probe reached only 3 of 10 tables (2 of 9 tenant-scoped): see "
        '"Not reached" above.' in _flat(after)
    )


def test_tables_not_reached_are_grouped_by_what_started_it():
    targets = ("public.a", "public.b", "public.c", "public.d", "public.e", "public.f", "public.g")
    skipped = (
        Skip("private.regions", "could not insert a synthetic row (23514): set values"),
        Skip("public.a", "needs a row of private.regions", "private.regions"),
        *(Skip(t, "needs a row of public.a", "public.a") for t in targets[1:6]),
        Skip("public.g", "no primary key to address its rows by"),
        Skip("auth.users", "could not create the synthetic users (42501)"),
    )
    coverage = _coverage(skipped=skipped, targets=(*targets, "public.h"), left_out=("public.z",))
    text = render_text(replace(_report(), probe=coverage))
    assert "Not reached (8 of 8 tables; fix them, or list them in [probe] skip_tables):" in text
    assert "  private.regions: could not insert a synthetic row (23514): set values" in text
    assert (
        "6 tables needed its row: public.a, public.b, public.c, public.d, public.e and 1 more"
        in _flat(text)
    )
    assert "  public.g: no primary key to address its rows by" in text
    assert "  public.h: no step ran to a conclusive outcome" in text
    assert "Left out by [probe] skip_tables: public.z" in text
    assert "  skipped auth.users: could not create the synthetic users (42501)" in text
    assert "public.b: needs a row" not in text  # one line for the whole group


def test_stand_ins_come_with_the_reason_their_row_was_missing():
    coverage = _coverage(
        probed=("public.tenants",),
        targets=("public.tenants",),
        skipped=(Skip("private.tiers", "could not insert a synthetic row (23514)"),),
        stand_ins=(
            StandIn("public.tenants", ("tier",), "private.tiers", existing=False),
            StandIn("public.projects", ("status",), "private.statuses", existing=True),
        ),
    )
    text = render_text(replace(_report(), probe=coverage))
    assert (
        "  private.tiers: could not insert a synthetic row (23514)\n"
        "    public.tenants.tier was left NULL instead\n"
        "  private.statuses: it has no synthetic row\n"
        "    public.projects.status took an existing row of it instead"
    ) in text


def test_coverage_in_json():
    coverage = _coverage(
        probed=("public.a",),
        targets=("public.a", "public.b"),
        scoped_targets=("public.b",),
        skipped=(Skip("public.b", "needs a row of public.x", "public.x"),),
        planned_steps=8,
        steps_run=4,
    )
    data = coverage.to_dict()
    assert data["complete"] is False
    assert data["tables"] == {"reached": 1, "of": 2}
    assert data["tenant_scoped_tables"] == {"reached": 0, "of": 1}
    assert data["steps"] == {"ran": 4, "planned": 8}
    assert data["not_reached"] == ["public.b"]
    assert data["skipped"] == [
        {"table": "public.b", "reason": "needs a row of public.x", "cause": "public.x"}
    ]
    assert coverage.ratio == 0.5


def test_blocked_probe_says_why():
    coverage = ProbeCoverage(
        "t", (), (), (), (), 0, blocked="the session user cannot SET ROLE anon"
    )
    text = render_text(replace(_report(), probe=coverage))
    assert "warning: the probe did not run, because the session user cannot SET ROLE anon." in text
    assert coverage.ratio == 0
    assert not coverage.complete


def test_no_probe_section_without_probe():
    assert "Probe:" not in render_text(_report())

"""The probe's rules: findings from hand-made observations, without a database."""

from __future__ import annotations

import random

import pytest
from factories import catalog, col, policy, table
from test_probe_plan import (
    _metadata_policy,
    app,
    comments,
    memberships,
    notes,
    plans,
    profiles,
    projects,
    tenants,
)

from se_check.audit import AuditPlan, audit_catalog
from se_check.config import AuditConfig
from se_check.models import Finding, Severity
from se_check.probe import ProbeResult
from se_check.probe.model import Observation, Outcome, ProbeCoverage
from se_check.probe.plan import plan_probe
from se_check.probe.rules import interpret, link_confirmations
from se_check.rules import select_rules
from se_check.settings import Acceptance


def _plan(cat):
    return plan_probe(cat, AuditConfig(), None, random.Random(0))


def _observe(probe_plan, outcomes):
    """`outcomes`: (table, persona, command[, scenario]) -> Outcome, or a predicate on steps;
    every other step comes out FILTERED."""

    def outcome(step):
        if callable(outcomes):
            return ALLOWED if outcomes(step) else Outcome.FILTERED
        key = (step.table_name, step.persona, step.command)
        return outcomes.get((*key, step.scenario), outcomes.get(key, Outcome.FILTERED))

    return [Observation(step, outcome(step)) for step in probe_plan.steps]


def _findings(outcomes, cat=None):
    cat = cat or app()
    probe_plan = _plan(cat)
    return interpret(cat, probe_plan, _observe(probe_plan, outcomes))


def _one(outcomes, cat=None) -> Finding:
    [finding] = _findings(outcomes, cat)
    return finding


ALLOWED = Outcome.ALLOWED


def test_nothing_reached_means_no_findings():
    assert _findings({}) == []


@pytest.mark.parametrize("outcome", [Outcome.FILTERED, Outcome.DENIED, Outcome.INCONCLUSIVE])
def test_only_allowed_steps_count(outcome):
    assert _findings({("public.projects", "alice", "SELECT"): outcome}) == []


# --- probe-anon-access ------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("command", "severity"),
    [
        ("SELECT", Severity.LOW),
        ("INSERT", Severity.MEDIUM),
        ("UPDATE", Severity.CRITICAL),
        ("DELETE", Severity.CRITICAL),
    ],
)
def test_anon_on_a_table_that_is_not_tenant_scoped(command, severity):
    finding = _one({("public.plans", "anon", command): ALLOWED})
    assert finding.check == "probe-anon-access"
    assert finding.object == "public.plans"
    assert finding.severity == severity
    assert finding.evidence["commands"] == command


def test_anon_on_a_tenant_scoped_table_is_critical_even_for_reads():
    finding = _one({("public.projects", "anon", "SELECT"): ALLOWED})
    assert finding.severity == Severity.CRITICAL
    assert "The rows belong to a tenant (tenant_id)" in finding.detail
    assert finding.evidence["tried"] == (
        "select exists(select 1 from public.projects where id = <row of tenant B>)"
    )


def test_anon_without_rls_suggests_enabling_it():
    open_plans = table(
        "plans", rls=False, details=(col("id", not_null=True), col("price", "int4", not_null=True))
    )
    cat = catalog(tables=[open_plans])
    finding = _one({("public.plans", "anon", "SELECT"): ALLOWED}, cat)
    assert finding.remediation.startswith("alter table public.plans enable row level security;")
    assert "Row Level Security is disabled" in finding.detail


def test_anon_names_the_policies_that_let_it_through():
    cat = app()
    cat = catalog(
        tables=cat.tables,
        policies=[policy("plans", name="plans are public", roles=("anon", "authenticated"))],
    )
    finding = _one({("public.plans", "anon", "SELECT"): ALLOWED}, cat)
    assert finding.evidence["policies"] == "plans are public"
    assert 'policy "plans are public" (SELECT, to anon, authenticated)' in finding.remediation


# --- probe-cross-tenant-read / -write ---------------------------------------------------------


def test_cross_tenant_read():
    finding = _one({("public.projects", "alice", "SELECT"): ALLOWED})
    assert finding.check == "probe-cross-tenant-read"
    assert finding.severity == Severity.HIGH
    assert finding.evidence["personas"] == "alice"
    assert "a member of tenant A" in finding.detail
    assert "with check" not in finding.remediation


def test_outsider_is_named_too():
    finding = _one(
        {
            ("public.projects", "alice", "SELECT"): ALLOWED,
            ("public.projects", "outsider", "SELECT"): ALLOWED,
        }
    )
    assert finding.evidence["personas"] == "alice, outsider"
    assert "and as a user who belongs to no tenant" in finding.detail


def _with_policies(*policies):
    return catalog(tables=app().tables, policies=policies)


def test_cross_tenant_write_groups_commands():
    cat = _with_policies(policy("projects", name="manage", command="ALL", using="true"))
    finding = _one(
        {
            ("public.projects", "alice", "INSERT"): ALLOWED,
            ("public.projects", "outsider", "DELETE"): ALLOWED,
        },
        cat,
    )
    assert finding.check == "probe-cross-tenant-write"
    assert finding.evidence["commands"] == "INSERT, DELETE"
    assert finding.title == "Users can insert and delete another tenant's rows"
    assert (
        "alter policy manage on public.projects using (<condition>) with check (<condition>);"
        in finding.remediation
    )


def test_cross_tenant_access_without_rls_suggests_enabling_it():
    open_projects = table(
        "projects",
        rls=False,
        privileges={"anon": frozenset(), "authenticated": frozenset({"SELECT"})},
        details=projects().column_details,
        foreign_keys=projects().foreign_keys,
    )
    tables = [t for t in app().tables if t.name != "projects"]
    finding = _one(
        {("public.projects", "alice", "SELECT"): ALLOWED}, catalog(tables=[*tables, open_projects])
    )
    assert finding.remediation.startswith("alter table public.projects enable row level security;")


def test_read_and_write_are_separate_findings():
    found = _findings(
        {
            ("public.projects", "alice", "SELECT"): ALLOWED,
            ("public.projects", "alice", "UPDATE"): ALLOWED,
        }
    )
    assert [f.check for f in found] == ["probe-cross-tenant-read", "probe-cross-tenant-write"]


def test_what_anon_can_do_is_not_reported_again_for_logged_in_users():
    found = _findings(
        {
            ("public.projects", "anon", "SELECT"): ALLOWED,
            ("public.projects", "alice", "SELECT"): ALLOWED,
            ("public.projects", "alice", "DELETE"): ALLOWED,
        }
    )
    assert [(f.check, f.evidence["commands"]) for f in found] == [
        ("probe-anon-access", "SELECT"),
        ("probe-cross-tenant-write", "DELETE"),
    ]


def test_policies_for_authenticated_are_listed():
    cat = catalog(
        tables=[tenants(), memberships(), projects(), comments(), profiles(), plans()],
        policies=[
            policy("projects", name="members read", using="true"),
            policy("projects", name="anon reads", roles=("anon",), using="true"),
        ],
    )
    finding = _one({("public.projects", "alice", "SELECT"): ALLOWED}, cat)
    assert finding.evidence["policies"] == "members read"
    assert 'alter policy "members read" on public.projects using (<condition>);' in (
        finding.remediation
    )


# --- confirmations and the audit --------------------------------------------------------------


def _static(check, obj):
    return Finding(check, Severity.HIGH, obj, "t", "d", "r")


def test_probe_findings_confirm_static_findings_on_the_same_table():
    probe = _findings({("public.projects", "alice", "SELECT"): ALLOWED})
    static = [_static("permissive-policy", "public.projects"), _static("x", "public.plans")]
    [linked] = link_confirmations(probe, static)
    assert linked.evidence["confirms"] == "permissive-policy"
    assert linked.detail.endswith("This confirms [permissive-policy] on the same table.")
    [alone] = link_confirmations(probe, [_static("x", "public.plans")])
    assert "confirms" not in alone.evidence


def _probe_result(outcomes):
    return ProbeResult(
        tuple(_findings(outcomes)),
        ProbeCoverage("t", (), ("public.projects",), (), (), 10),
    )


def test_audit_merges_probe_findings_and_applies_acceptances():
    cat = app()
    probe = _probe_result(
        {
            ("public.projects", "alice", "SELECT"): ALLOWED,
            ("public.plans", "anon", "SELECT"): ALLOWED,
        }
    )
    accepted = (Acceptance("probe-anon-access", "public.plans", "Pricing is public."),)
    report = audit_catalog(cat, AuditPlan(accepted=accepted), probe=probe)
    assert [f.check for f in report.findings] == ["probe-cross-tenant-read"]
    assert [a.finding.check for a in report.accepted] == ["probe-anon-access"]
    assert report.probe == probe.coverage
    assert report.to_dict()["probe"]["statements"] == 10


def test_selecting_only_probe_rules_runs_no_static_check():
    open_table = table("open", rls=False)
    cat = catalog(tables=[*app().tables, open_table])
    probe = _probe_result({("public.projects", "alice", "SELECT"): ALLOWED})
    report = audit_catalog(cat, AuditConfig(), ["probe-cross-tenant-read"], probe=probe)
    assert [f.check for f in report.findings] == ["probe-cross-tenant-read"]
    static_only = audit_catalog(cat, AuditConfig(), ["rls-disabled"], probe=probe)
    assert [f.check for f in static_only.findings] == ["rls-disabled"]


def test_probe_rules_need_the_probe():
    with pytest.raises(ValueError, match="probe-anon-access come"):
        select_rules(["probe-anon-access"], probe=False)
    with pytest.raises(ValueError, match="unknown check"):
        select_rules(["nope"], probe=True)
    checks, probe_rules = select_rules(None, probe=False)
    assert probe_rules == () and checks


def test_report_without_probe_says_so():
    assert audit_catalog(app(), AuditConfig()).to_dict()["probe"] is None


# --- probe-cross-user-read / -write -----------------------------------------------------------


def test_cross_user_read():
    finding = _one({("public.notes", "alice", "SELECT"): ALLOWED}, app(notes()))
    assert finding.check == "probe-cross-user-read"
    assert finding.title == "Users can read other users' rows"
    assert "read a synthetic row belonging to bob" in finding.detail
    assert "The rows belong to a user (user_id)." in finding.detail
    assert "user_id = (select auth.uid())" in finding.remediation
    assert finding.evidence["tried"] == (
        "select exists(select 1 from public.notes where id = <row of bob's>)"
    )


def test_cross_user_insert_is_writing_in_someone_elses_name():
    finding = _one({("public.notes", "outsider", "INSERT"): ALLOWED}, app(notes()))
    assert finding.check == "probe-cross-user-write"
    assert "inserted a row in bob's name." in finding.detail
    assert "filtered on the primary key" not in finding.detail
    assert finding.evidence["tried"] == "insert into public.notes a row in bob's name"


def test_anon_on_rows_owned_by_users_is_critical():
    finding = _one({("public.notes", "anon", "SELECT"): ALLOWED}, app(notes()))
    assert finding.severity == Severity.CRITICAL
    assert "read a synthetic row belonging to bob" in finding.detail
    assert "The rows belong to a user (user_id)" in finding.detail


# --- tenant hop, self-escalation, mallory -----------------------------------------------------


def _on_profiles(step):
    return step.table_name == "public.profiles" and step.scenario == "self-escalation"


def test_tenant_hop_is_a_cross_tenant_write():
    finding = _one({("public.projects", "alice", "UPDATE", "tenant-hop"): ALLOWED})
    assert finding.check == "probe-cross-tenant-write"
    assert "moved a row of tenant A into tenant B" in finding.detail
    assert finding.evidence["tried"] == (
        "update public.projects set tenant_id = <tenant B> where id = <row of tenant A>"
    )


def test_self_escalation():
    def role_to_admin(step):
        return _on_profiles(step) and step.set_column == "role" and step.value_label == "'admin'"

    finding = _one(role_to_admin)
    assert finding.check == "probe-self-escalation"
    assert finding.object == "public.profiles"
    assert finding.title == "Users can set their own role"
    assert "updated her own row, setting role to 'admin'." in finding.detail
    assert finding.remediation.startswith(
        "revoke update on public.profiles from authenticated;\n"
        "grant update (<the columns users may change>) on public.profiles to authenticated;"
    )
    assert finding.evidence["tried"] == (
        "update public.profiles set role = 'admin' where id = <alice's own row>"
    )


def test_moving_her_own_profile_is_joining_tenant_b():
    finding = _one(lambda step: _on_profiles(step) and step.set_column == "tenant_id")
    assert finding.title == "Users can set their own tenant_id"
    assert "now it is tenant B" in finding.detail


def test_self_escalation_is_not_folded_into_anon():
    def allowed(step):
        return step.table_name == "public.profiles" and (
            step.persona == "anon" or step.set_column == "role"
        )

    assert {f.check for f in _findings(allowed)} == {"probe-anon-access", "probe-self-escalation"}


def test_mallory_alone_points_at_user_metadata():
    cat = catalog(tables=app().tables, policies=[_metadata_policy()])
    finding = _one({("public.projects", "mallory", "SELECT"): ALLOWED}, cat)
    assert finding.evidence["personas"] == "mallory"
    assert "supabase.auth.updateUser()" in finding.detail
    assert "the policies take the tenant from user_metadata" in finding.detail
    assert finding.remediation.startswith("Take the tenant from a table users cannot write")


def test_mallory_adds_nothing_when_any_user_gets_through():
    cat = catalog(tables=app().tables, policies=[_metadata_policy()])
    finding = _one(
        lambda step: (
            step.table_name == "public.projects"
            and step.command == "SELECT"
            and step.persona in ("mallory", "outsider")
        ),
        cat,
    )
    assert finding.evidence["personas"] == "mallory, outsider"
    assert "user_metadata" not in finding.detail


def test_confirmations_only_link_the_same_hole():
    static = [_static("user-metadata-auth", "public.profiles")]
    read = _findings({("public.profiles", "alice", "SELECT"): ALLOWED})
    raised = _findings(lambda step: _on_profiles(step) and step.set_column == "role")
    assert link_confirmations(read, static)[0].evidence["confirms"] == "user-metadata-auth"
    assert "confirms" not in link_confirmations(raised, static)[0].evidence

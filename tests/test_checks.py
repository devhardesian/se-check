"""Unit tests for the checks, on hand-made catalogs."""

from __future__ import annotations

import pytest
from factories import ALL, catalog, function, policy, run, table

from se_check.checks import ALL_CHECKS, run_checks, select_checks
from se_check.checks.functions import DEFINER_NO_CALLER_CHECK, DEFINER_SEARCH_PATH
from se_check.checks.policies import (
    ALWAYS_TRUE,
    ANY_LOGGED_IN,
    PERMISSIVE_POLICY,
    USER_METADATA_AUTH,
    classify_expression,
)
from se_check.checks.rls import RLS_DISABLED
from se_check.config import AuditConfig
from se_check.models import Severity

TENANT_COLUMNS = ("id", "tenant_id", "title")


# --- rls-disabled ---------------------------------------------------------------------------


def test_rls_disabled_on_exposed_table_is_critical():
    [finding] = run(RLS_DISABLED, catalog(tables=[table("invoices", rls=False)]))
    assert finding.severity == Severity.CRITICAL
    assert finding.object == "public.invoices"
    assert "anon: SELECT, INSERT, UPDATE, DELETE" in finding.evidence["grants"]
    assert "enable row level security" in finding.remediation


def test_rls_disabled_without_grants_is_low():
    cat = catalog(tables=[table("audit_log", rls=False, privileges={})])
    [finding] = run(RLS_DISABLED, cat)
    assert finding.severity == Severity.LOW


def test_rls_enabled_is_quiet():
    assert run(RLS_DISABLED, catalog(tables=[table("projects")])) == []


# --- permissive-policy: expression classification --------------------------------------------


@pytest.mark.parametrize(
    ("expression", "expected"),
    [
        # Exactly as Postgres deparses them in pg_policies.
        ("true", ALWAYS_TRUE),
        ("(1 = 1)", ALWAYS_TRUE),
        ("(auth.uid() IS NOT NULL)", ANY_LOGGED_IN),
        ("(( SELECT auth.uid() AS uid) IS NOT NULL)", ANY_LOGGED_IN),
        ("(auth.role() = 'authenticated'::text)", ANY_LOGGED_IN),
        ("(( SELECT auth.role() AS role) = 'authenticated'::text)", ANY_LOGGED_IN),
        ("((auth.jwt() ->> 'role'::text) = 'authenticated'::text)", ANY_LOGGED_IN),
        ("(user_id = auth.uid())", None),
        ("(true AND (tenant_id = private.current_tenant()))", None),
        ("(auth.uid() IS NOT NULL) AND (owner = auth.uid())", None),
        (None, None),
    ],
)
def test_classify_expression(expression, expected):
    assert classify_expression(expression) == expected


# --- permissive-policy ------------------------------------------------------------------------


def test_select_true_on_tenant_table_is_high():
    cat = catalog(
        tables=[table("documents", columns=TENANT_COLUMNS)],
        policies=[policy("documents", using="true")],
    )
    [finding] = run(PERMISSIVE_POLICY, cat)
    assert finding.severity == Severity.HIGH
    assert "tenant_id" in finding.detail
    assert finding.evidence["policy"] == "p"


def test_select_true_on_reference_table_is_low():
    cat = catalog(tables=[table("plans")], policies=[policy("plans", using="true")])
    [finding] = run(PERMISSIVE_POLICY, cat)
    assert finding.severity == Severity.LOW


def test_insert_true_is_medium_or_high_depending_on_tenancy():
    open_insert = {"command": "INSERT", "roles": ("anon",), "with_check": "true"}
    feedback = catalog(tables=[table("feedback")], policies=[policy("feedback", **open_insert)])
    notes = catalog(
        tables=[table("notes", columns=TENANT_COLUMNS)], policies=[policy("notes", **open_insert)]
    )
    assert [f.severity for f in run(PERMISSIVE_POLICY, feedback)] == [Severity.MEDIUM]
    assert [f.severity for f in run(PERMISSIVE_POLICY, notes)] == [Severity.HIGH]


def test_delete_true_is_high_even_without_tenant_column():
    cat = catalog(
        tables=[table("profiles")], policies=[policy("profiles", command="DELETE", using="true")]
    )
    assert [f.severity for f in run(PERMISSIVE_POLICY, cat)] == [Severity.HIGH]


def test_all_policy_that_only_checks_login_opens_every_command():
    cat = catalog(
        tables=[table("tasks", columns=TENANT_COLUMNS)],
        policies=[
            policy("tasks", command="ALL", using="(( SELECT auth.uid() AS uid) IS NOT NULL)")
        ],
    )
    [finding] = run(PERMISSIVE_POLICY, cat)
    assert finding.severity == Severity.HIGH
    assert "read, inserted, updated or deleted" in finding.title
    assert "logged in" in finding.detail


def test_update_with_loose_check_only_is_medium():
    cat = catalog(
        tables=[table("profiles")],
        policies=[
            policy("profiles", command="UPDATE", using="(id = auth.uid())", with_check="true")
        ],
    )
    [finding] = run(PERMISSIVE_POLICY, cat)
    assert finding.severity == Severity.MEDIUM
    assert "with check (<condition>)" in finding.remediation
    assert "using (<condition>)" not in finding.remediation


def test_policy_to_public_applies_to_api_roles():
    cat = catalog(
        tables=[table("documents", columns=TENANT_COLUMNS)],
        policies=[policy("documents", roles=("public",), using="true")],
    )
    [finding] = run(PERMISSIVE_POLICY, cat)
    assert "anon, authenticated" in finding.detail


@pytest.mark.parametrize(
    "quiet_policy",
    [
        policy("documents", using="(tenant_id IN ( SELECT my_tenant_ids() AS my_tenant_ids))"),
        policy("documents", using="true", permissive=False),
        policy("documents", using="true", roles=("service_role",)),
        # No expression at all: Postgres treats it as false.
        policy("documents", command="INSERT"),
    ],
    ids=["scoped", "restrictive", "non-api-role", "no-expression"],
)
def test_policies_that_restrict_rows_are_quiet(quiet_policy):
    cat = catalog(tables=[table("documents", columns=TENANT_COLUMNS)], policies=[quiet_policy])
    assert run(PERMISSIVE_POLICY, cat) == []


def test_open_policy_is_quiet_when_the_role_has_no_privilege():
    cat = catalog(
        tables=[table("documents", privileges={"authenticated": frozenset({"INSERT"})})],
        policies=[policy("documents", using="true")],
    )
    assert run(PERMISSIVE_POLICY, cat) == []


def test_configured_tenant_column_is_used():
    cat = catalog(
        tables=[table("documents", columns=("id", "clinic_id"))],
        policies=[policy("documents", using="true")],
    )
    [finding] = run(PERMISSIVE_POLICY, cat, tenant_columns=("clinic_id",))
    assert finding.severity == Severity.HIGH


# --- user-metadata-auth -----------------------------------------------------------------------


def test_policy_reading_user_metadata_is_high():
    expr = "(tenant_id = (((auth.jwt() -> 'user_metadata'::text) ->> 'tenant_id'::text))::uuid)"
    cat = catalog(tables=[table("profiles")], policies=[policy("profiles", using=expr)])
    [finding] = run(USER_METADATA_AUTH, cat)
    assert finding.severity == Severity.HIGH
    assert finding.object == "public.profiles"


def test_app_metadata_is_fine():
    expr = "(tenant_id = (((auth.jwt() -> 'app_metadata'::text) ->> 'tenant_id'::text))::uuid)"
    cat = catalog(tables=[table("profiles")], policies=[policy("profiles", using=expr)])
    assert run(USER_METADATA_AUTH, cat) == []


def test_helper_reading_user_metadata_is_flagged_when_policies_use_it():
    helper = function(
        "tenant_from_metadata",
        schema="private",
        body="select (raw_user_meta_data ->> 'tenant_id')::uuid from auth.users",
    )
    cat = catalog(
        tables=[table("comments")],
        policies=[
            policy("comments", name="read", using="(tenant_id = private.tenant_from_metadata())")
        ],
        functions=[helper],
    )
    [finding] = run(USER_METADATA_AUTH, cat)
    assert finding.object == "private.tenant_from_metadata()"
    assert 'public.comments: "read"' in finding.evidence["policies"]


def test_helper_reading_user_metadata_is_quiet_when_no_policy_uses_it():
    helper = function("display_name", body="select raw_user_meta_data ->> 'name' from auth.users")
    assert run(USER_METADATA_AUTH, catalog(functions=[helper])) == []


def test_user_metadata_in_a_comment_does_not_count():
    helper = function("tenant", body="-- never use raw_user_meta_data here\nselect 1")
    cat = catalog(
        tables=[table("comments")],
        policies=[policy("comments", using="(tenant_id = tenant())")],
        functions=[helper],
    )
    assert run(USER_METADATA_AUTH, cat) == []


# --- definer-no-caller-check ------------------------------------------------------------------

UNCHECKED = "begin delete from public.tenants where id = p_tenant; end"


def test_definer_without_caller_check_is_high():
    cat = catalog(functions=[function("delete_tenant", body=UNCHECKED, arguments="p_tenant uuid")])
    [finding] = run(DEFINER_NO_CALLER_CHECK, cat)
    assert finding.severity == Severity.HIGH
    assert finding.object == "public.delete_tenant(p_tenant uuid)"
    assert "/rest/v1/rpc/delete_tenant" in finding.detail
    assert "from public, anon, authenticated" in finding.remediation


@pytest.mark.parametrize(
    "body",
    [
        "begin if auth.uid() is null then raise exception 'no'; end if; end",
        "select * from t where owner = (select auth.uid())",
        "select (auth.jwt() ->> 'sub')::uuid",
        "select current_setting('request.jwt.claims', true)",
    ],
)
def test_definer_reading_caller_identity_is_quiet(body):
    assert run(DEFINER_NO_CALLER_CHECK, catalog(functions=[function("f", body=body)])) == []


def test_caller_check_in_a_comment_does_not_count():
    body = "/* TODO: check auth.uid() */ begin delete from t; end"
    assert len(run(DEFINER_NO_CALLER_CHECK, catalog(functions=[function("f", body=body)]))) == 1


GUARDED_BODY = "begin if not private.has_permission(t, 'w') then raise exception 'x'; end if; end"


def test_helper_reading_caller_identity_counts_as_caller_check():
    helper = function(
        "has_permission",
        schema="private",
        body="select exists (select 1 from m where m.user_id = auth.uid())",
    )
    cat = catalog(functions=[helper, function("rename", body=GUARDED_BODY)])
    assert run(DEFINER_NO_CALLER_CHECK, cat) == []


def test_caller_check_is_followed_through_a_chain_of_helpers():
    cat = catalog(
        functions=[
            function("current_member", schema="private", body="select auth.uid()"),
            function("has_permission", schema="private", body="select current_member() = x"),
            function("rename", body=GUARDED_BODY),
        ]
    )
    assert run(DEFINER_NO_CALLER_CHECK, cat) == []


def test_helper_that_ignores_the_caller_does_not_count():
    helper = function("has_permission", schema="private", body="select true")
    cat = catalog(functions=[helper, function("rename", body=GUARDED_BODY)])
    [finding] = run(DEFINER_NO_CALLER_CHECK, cat)
    assert finding.object == "public.rename()"


def test_configured_guard_counts_as_caller_check():
    # A helper whose source se-check cannot read (here: not in the catalog at all).
    cat = catalog(functions=[function("rename", body=GUARDED_BODY)])
    assert len(run(DEFINER_NO_CALLER_CHECK, cat)) == 1
    assert run(DEFINER_NO_CALLER_CHECK, cat, guard_functions=("has_permission",)) == []


@pytest.mark.parametrize(
    "fn",
    [
        function("f", body=UNCHECKED, definer=False),
        function("f", body=UNCHECKED, executable_by=frozenset()),
        function("f", body=UNCHECKED, schema="private"),
        function("f", body=UNCHECKED, is_trigger=True),
    ],
    ids=["invoker", "not-executable", "not-exposed", "trigger"],
)
def test_functions_out_of_reach_are_quiet(fn):
    assert run(DEFINER_NO_CALLER_CHECK, catalog(functions=[fn])) == []


# --- definer-search-path ----------------------------------------------------------------------


def test_mutable_search_path_is_medium_when_callable_and_low_otherwise():
    cat = catalog(
        functions=[
            function("exposed", config=()),
            function("internal", config=(), schema="private"),
            function("pinned"),
            function("invoker", config=(), definer=False),
        ]
    )
    findings = {f.object: f.severity for f in run(DEFINER_SEARCH_PATH, cat)}
    assert findings == {"public.exposed()": Severity.MEDIUM, "private.internal()": Severity.LOW}


# --- registry ---------------------------------------------------------------------------------


def test_check_ids_are_unique():
    ids = [check.id for check in ALL_CHECKS]
    assert len(ids) == len(set(ids))


def test_select_checks_rejects_unknown_ids():
    with pytest.raises(ValueError, match="nope"):
        select_checks(["rls-disabled", "nope"])


def test_run_checks_sorts_by_severity():
    cat = catalog(
        tables=[table("plans"), table("invoices", rls=False)],
        policies=[policy("plans", using="true")],
    )
    findings = run_checks(cat, AuditConfig())
    assert [f.severity for f in findings] == [Severity.CRITICAL, Severity.LOW]


def test_findings_never_carry_row_data():
    # Findings are built from catalog metadata only; make sure that stays visible in the API.
    cat = catalog(tables=[table("invoices", rls=False, privileges={"anon": ALL})])
    [finding] = run_checks(cat, AuditConfig())
    assert set(finding.to_dict()) == {
        "check",
        "severity",
        "object",
        "title",
        "detail",
        "remediation",
        "evidence",
    }

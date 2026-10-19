"""End-to-end on a real Postgres loaded with examples/vulnerable-app."""

from __future__ import annotations

import psycopg
import pytest

from se_check.audit import AuditError, run_audit
from se_check.catalog import load_catalog
from se_check.config import AuditConfig
from se_check.db import connect

# One entry per VULN tag in examples/vulnerable-app/10_acme_notes.sql.
EXPECTED = {
    ("rls-disabled", "public.invoices", "critical"),
    ("rls-disabled", "public.audit_log", "low"),
    ("permissive-policy", "public.documents", "high"),
    ("permissive-policy", "public.tasks", "high"),
    ("permissive-policy", "public.plans", "low"),
    ("permissive-policy", "public.feedback", "medium"),
    ("user-metadata-auth", "public.profiles", "high"),
    ("user-metadata-auth", "private.tenant_from_metadata()", "high"),
    ("definer-no-caller-check", "public.delete_tenant(p_tenant uuid)", "high"),
    ("definer-search-path", "public.delete_tenant(p_tenant uuid)", "medium"),
    ("definer-search-path", "private.purge_old_audit_log()", "low"),
    ("auth-hook-exposed", "public.custom_access_token_hook(event jsonb)", "high"),
    ("signup-trigger-metadata", "public.join_tenant_on_signup()", "high"),
    ("permissive-policy", "public.messages", "low"),
}

# One entry per probe-* tag: what `audit --probe` adds to EXPECTED.
EXPECTED_PROBE = {
    ("probe-anon-access", "public.invoices", "critical"),
    ("probe-anon-access", "public.plans", "low"),
    ("probe-anon-access", "public.feedback", "medium"),
    ("probe-cross-tenant-read", "public.documents", "high"),
    ("probe-cross-tenant-read", "public.tasks", "high"),
    ("probe-cross-tenant-write", "public.tasks", "high"),
    ("probe-cross-tenant-read", "public.profiles", "high"),
    ("probe-cross-tenant-read", "public.comments", "high"),
    ("probe-self-escalation", "public.profiles", "high"),
    ("probe-cross-user-read", "public.messages", "high"),
}


def _found(report) -> set[tuple[str, str, str]]:
    return {(f.check, f.object, f.severity.label) for f in report.findings}


def test_example_app_findings_match_its_annotations(example_dsn):
    # No configuration: rename_project() checks the caller through has_permission(), which
    # se-check must work out by itself.
    report = run_audit(example_dsn, AuditConfig())
    assert _found(report) == EXPECTED
    assert report.missing_api_roles == ()


def test_catalog_snapshot(example_dsn):
    with connect(example_dsn) as conn:
        catalog = load_catalog(conn, AuditConfig())

    assert catalog.api_roles == ("anon", "authenticated")
    invoices = catalog.table("public", "invoices")
    assert invoices is not None
    assert not invoices.rls_enabled
    assert "tenant_id" in invoices.columns
    assert invoices.has_privilege("anon", "SELECT")
    assert not catalog.table("public", "audit_log").privileges

    functions = {f.signature: f for f in catalog.functions}
    assert functions["public.handle_new_user()"].is_trigger
    assert functions["public.refresh_stats()"].executable_by == frozenset()
    assert "private.my_tenant_ids()" in functions  # policies' helpers are loaded too
    assert not any(f.schema == "auth" for f in catalog.functions)  # managed schema
    assert "public.extension_owned()" not in functions  # see conftest
    assert functions["public.custom_access_token_hook(event jsonb)"].granted_to_auth_admin
    assert not functions["public.my_projects()"].granted_to_auth_admin
    assert {t.name for t in catalog.auth_user_triggers} == {
        "on_auth_user_created",
        "on_auth_user_created_join_tenant",
    }


def test_audit_connection_is_read_only(example_dsn):
    with connect(example_dsn) as conn, pytest.raises(psycopg.errors.ReadOnlySqlTransaction):
        conn.execute("create table public.should_not_exist ()")


def test_missing_api_roles_are_reported(example_dsn):
    report = run_audit(example_dsn, AuditConfig(api_roles=("anon", "web_user")))
    assert report.missing_api_roles == ("web_user",)


def test_connection_errors_become_audit_errors():
    with pytest.raises(AuditError, match="database error"):
        run_audit("postgresql://nobody@127.0.0.1:1/none?connect_timeout=2", AuditConfig())

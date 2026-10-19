"""The dynamic probe end to end, on a real Postgres loaded with examples/vulnerable-app."""

from __future__ import annotations

import json
import uuid

import psycopg
import pytest
from test_integration import EXPECTED, EXPECTED_PROBE

from se_check.audit import AuditPlan, run_audit
from se_check.config import AuditConfig, ProbeConfig
from se_check.report import render_text


def _found(report, *, probe: bool) -> set[tuple[str, str, str]]:
    return {
        (f.check, f.object, f.severity.label)
        for f in report.findings
        if f.check.startswith("probe-") == probe
    }


@pytest.mark.parametrize("dsn_fixture", ["example_dsn", "supabase_role_dsn"])
def test_example_app_probe_findings_match_its_annotations(dsn_fixture, request):
    report = run_audit(request.getfixturevalue(dsn_fixture), AuditConfig(), probe=True)
    assert _found(report, probe=True) == EXPECTED_PROBE
    assert _found(report, probe=False) == EXPECTED  # the static checks are unchanged
    coverage = report.probe
    assert coverage.inconclusive == ()
    # The SAFE tables were tried, not skipped: their silence means something.
    assert {"public.projects", "public.memberships", "public.tenants"} <= set(coverage.probed)
    assert coverage.complete
    assert len(coverage.targets) == 12
    assert coverage.steps_run == coverage.planned_steps
    assert coverage.tenancy == (
        "tenants in public.tenants, 8 tenant-scoped tables; 2 tables of rows owned by a user"
    )
    # Reference data the probe can't make rows of (a CHECK on the codes): stand-ins.
    assert {s.describe() for s in coverage.stand_ins} == {
        "public.tenants.tier was left NULL instead",
        "public.projects.status took an existing row of it instead",
    }
    assert {s.table for s in coverage.skipped} == {"private.tiers", "private.project_statuses"}


def test_probe_findings_confirm_the_static_ones(example_dsn):
    report = run_audit(example_dsn, AuditConfig(), probe=True)
    confirms = {
        f.object: f.evidence.get("confirms")
        for f in report.findings
        if f.check.startswith("probe-")
    }
    assert confirms["public.invoices"] == "rls-disabled"
    assert confirms["public.documents"] == "permissive-policy"


def _snapshot(dsn: str) -> dict[str, int]:
    with psycopg.connect(dsn) as conn:
        tables = conn.execute(
            "select format('%I.%I', schemaname, tablename) from pg_tables"
            " where schemaname in ('public', 'auth') order by 1"
        ).fetchall()
        counts = {
            name: conn.execute(f"select count(*) from {name}").fetchone()[0] for (name,) in tables
        }
        counts["roles"] = conn.execute("select count(*) from pg_roles").fetchone()[0]
        counts["relations"] = conn.execute("select count(*) from pg_class").fetchone()[0]
    return counts


def test_probe_leaves_the_database_as_it_was(example_dsn):
    before = _snapshot(example_dsn)
    run_audit(example_dsn, AuditConfig(), probe=True)
    assert _snapshot(example_dsn) == before


def test_rows_of_the_application_never_reach_the_report(fresh_example):
    dsn = fresh_example()
    secret = f"s3cret-{uuid.uuid4().hex}"
    tenant, user = uuid.uuid4(), uuid.uuid4()
    with psycopg.connect(dsn, autocommit=True) as conn:
        conn.execute("insert into auth.users (id, email) values (%s, %s)", (user, f"{secret}@x"))
        conn.execute("insert into public.tenants (id, name) values (%s, %s)", (tenant, secret))
        for statement in (
            "insert into public.documents (tenant_id, title, body) values (%(t)s, %(s)s, %(s)s)",
            "insert into public.tasks (tenant_id, title) values (%(t)s, %(s)s)",
            "insert into public.invoices (tenant_id, amount_cents) values (%(t)s, 4242)",
            "insert into public.comments (tenant_id, body) values (%(t)s, %(s)s)",
            "insert into public.plans (id, name, price_cents) values (%(s)s, %(s)s, 1)",
            "insert into public.feedback (message) values (%(s)s)",
        ):
            conn.execute(statement, {"t": tenant, "s": secret})

    report = run_audit(dsn, AuditConfig(), probe=True)
    assert secret not in json.dumps(report.to_dict())
    assert secret not in render_text(report)
    assert _found(report, probe=True) == EXPECTED_PROBE  # real rows change nothing


def _regions(dsn: str, *codes: str) -> None:
    """Every tenant has a region: reference data the probe can't make a row of."""
    with psycopg.connect(dsn, autocommit=True) as conn:
        conn.execute(
            "create table private.regions (code text primary key check (code ~ '^[a-z]+$'))"
        )
        for code in codes:
            conn.execute("insert into private.regions values (%s)", (code,))
        conn.execute(
            "alter table public.tenants add column region text not null"
            " references private.regions (code)"
        )


def test_a_missing_row_everyone_needs_is_named_as_the_cause(fresh_example):
    """One row missing, most tables skipped: the report must not look clean."""
    dsn = fresh_example()
    _regions(dsn)  # no regions at all: nothing to stand in
    report = run_audit(dsn, AuditConfig(), probe=True)
    coverage = report.probe
    assert not coverage.complete
    assert set(coverage.reached) == {
        "public.plans",
        "public.feedback",
        "public.notes",
        "public.messages",
    }
    skipped = {s.table: s for s in coverage.skipped}
    assert skipped["public.tenants"].cause == "private.regions"
    assert skipped["public.tenants"].reason == (
        "needs a row of private.regions, which has no synthetic row, and no existing row "
        "se-check could use"
    )
    assert skipped["public.tasks"].cause == "public.tenants"
    assert "23514" in skipped["private.regions"].reason

    text = " ".join(render_text(report).split())
    assert (
        "warning: the probe reached 4 of 12 tables (0 of 7 tenant-scoped), with "
        in text.split("CRITICAL")[0]
    )
    assert "8 of them because private.regions got no synthetic row." in text
    assert (
        '[probe.values."private.regions"] 8 tables needed its row: public.comments, '
        "public.documents, public.invoices, public.memberships, public.profiles and 3 more" in text
    )
    assert "warning: the probe reached only 4 of 12 tables" in text
    # The probe findings on the tables it did reach are still there.
    assert ("probe-anon-access", "public.plans", "low") in _found(report, probe=True)


def test_an_existing_row_stands_in_without_reaching_the_report(fresh_example):
    dsn = fresh_example()
    secret = "zz" + "".join(chr(ord("a") + int(c, 16) % 26) for c in uuid.uuid4().hex)
    _regions(dsn, secret)
    report = run_audit(dsn, AuditConfig(), probe=True)
    assert report.probe.complete
    assert _found(report, probe=True) == EXPECTED_PROBE
    assert any(
        s.table == "public.tenants" and s.existing and s.parent == "private.regions"
        for s in report.probe.stand_ins
    )
    assert secret not in json.dumps(report.to_dict())
    assert secret not in render_text(report)


def test_probe_gives_up_on_locked_tables_instead_of_waiting(fresh_example):
    dsn = fresh_example()
    with psycopg.connect(dsn) as locker:
        # SHARE blocks writes, not reads: the catalog still loads, the synthetic rows can't.
        locker.execute("lock table public.tasks in share mode")
        report = run_audit(dsn, AuditConfig(), probe=True)
        locker.rollback()
    skipped = {s.table: s.reason for s in report.probe.skipped}
    assert "55P03" in skipped["public.tasks"]  # lock_timeout
    assert _found(report, probe=True) == {f for f in EXPECTED_PROBE if f[1] != "public.tasks"}


def test_tables_whose_triggers_reach_outside_the_transaction_are_left_alone(fresh_example):
    dsn = fresh_example()
    with psycopg.connect(dsn, autocommit=True) as conn:
        conn.execute(
            "create function public.notify_crm() returns trigger language plpgsql as $$"
            " begin perform http_post('https://crm.invalid', '{}'); return new; end $$"
        )
        conn.execute(
            "create trigger notify_crm after insert on public.tasks"
            " for each row execute function public.notify_crm()"
        )
    report = run_audit(dsn, AuditConfig(), probe=True)
    skipped = {s.table: s.reason for s in report.probe.skipped}
    assert "notify_crm()" in skipped["public.tasks"]
    assert "public.tasks" not in report.probe.probed


def _memos(dsn: str, claim: str, using: str | None = None) -> None:
    """A tenant-scoped table whose policy only checks that the JWT names *a* tenant."""
    using = using or f"((auth.jwt() -> 'app_metadata') ->> '{claim}') is not null"
    with psycopg.connect(dsn, autocommit=True) as conn:
        conn.execute(
            "create table public.memos (id uuid primary key default gen_random_uuid(),"
            " tenant_id uuid not null references public.tenants (id), body text not null)"
        )
        conn.execute("alter table public.memos enable row level security")
        # "Has a tenant" is not "has this tenant": anyone with the claim gets through.
        conn.execute(
            'create policy "users with a tenant" on public.memos for select to authenticated'
            f" using ({using})"
        )


def _memo_findings(report):
    return [f for f in report.findings if f.object == "public.memos"]


def test_tenant_claims_read_by_policies_are_given_to_the_personas(fresh_example):
    dsn = fresh_example()
    _memos(dsn, "tenant_id")
    report = run_audit(dsn, AuditConfig(), ["probe-cross-tenant-read"], probe=True)
    [finding] = _memo_findings(report)
    assert finding.evidence["personas"] == "alice"  # the outsider has no tenant to claim
    assert "app_metadata.tenant_id (read by your policies)" in report.probe.claims


def test_configured_claims_and_membership(fresh_example):
    """A claim se-check can't recognize as a tenant, and a membership the catalog can't show:
    both from [probe] in se-check.toml."""
    dsn = fresh_example()
    _memos(dsn, "company")
    with psycopg.connect(dsn, autocommit=True) as conn:
        conn.execute("create table public.seats (user_id uuid, tenant_id uuid)")
    only = ["probe-cross-tenant-read"]

    # Without the claim no persona looks like a real user, and the hole stays hidden.
    assert not _memo_findings(run_audit(dsn, AuditConfig(), only, probe=True))

    probe = ProbeConfig(
        claims={"app_metadata": {"company": "{tenant}"}},
        membership="insert into public.seats values (%(user)s, %(tenant)s)",
    )
    report = run_audit(dsn, AuditPlan(probe=probe), only, probe=True)
    [finding] = _memo_findings(report)
    assert finding.evidence["personas"] == "alice"
    assert "app_metadata.company (from [probe] claims)" in report.probe.claims
    assert any("membership from [probe] membership" in p for p in report.probe.personas)


def test_probe_refuses_to_guess_when_it_cannot_become_the_api_roles(fresh_example, server_dsn):
    """Without SET ROLE every step would fail and look like a denial: no findings, wrongly."""
    dsn = fresh_example()
    role, password = f"se_check_plain_{uuid.uuid4().hex[:8]}", uuid.uuid4().hex
    with psycopg.connect(server_dsn, autocommit=True) as admin:
        admin.execute(f"create role {role} login password '{password}'")
    with psycopg.connect(dsn, autocommit=True) as owner:
        owner.execute(f"grant usage on schema auth to {role}")  # the static audit needs it
    try:
        conninfo = psycopg.conninfo.conninfo_to_dict(dsn)
        as_role = psycopg.conninfo.make_conninfo(**{**conninfo, "user": role, "password": password})
        report = run_audit(as_role, AuditConfig(), probe=True)
        assert "cannot SET ROLE anon (42501)" in report.probe.blocked
        assert not _found(report, probe=True)
        assert report.probe.statements == 0
    finally:
        with psycopg.connect(dsn, autocommit=True) as owner:
            owner.execute(f"revoke usage on schema auth from {role}")
        with psycopg.connect(server_dsn, autocommit=True) as admin:
            admin.execute(f"drop role {role}")


def test_claims_from_the_custom_access_token_hook(fresh_example):
    """Claims only the hook adds (here: a group for members) reach the personas' JWTs."""
    dsn = fresh_example()
    with psycopg.connect(dsn, autocommit=True) as conn:
        conn.execute(
            "create or replace function public.custom_access_token_hook(event jsonb)"
            " returns jsonb language plpgsql stable security definer set search_path = '' as $$"
            " declare claims jsonb := coalesce(event -> 'claims', '{}'); begin"
            "   if exists (select 1 from public.memberships"
            "              where user_id = (event ->> 'user_id')::uuid) then"
            "     claims := jsonb_set(claims, '{groups}', '[\"staff\"]');"
            "   end if;"
            "   return jsonb_set(event, '{claims}', claims);"
            " end $$"
        )
    _memos(dsn, "", using="(auth.jwt() -> 'groups') ? 'staff'")  # staff of any tenant
    report = run_audit(dsn, AuditConfig(), ["probe-cross-tenant-read"], probe=True)
    [finding] = _memo_findings(report)
    assert finding.evidence["personas"] == "alice"  # a member: the hook made her staff
    assert any("custom_access_token_hook()" in source for source in report.probe.claims)


def test_tenancy_in_a_private_schema(fresh_example):
    """The tenant table and the memberships live in `private`, out of the API's reach."""
    dsn = fresh_example(stub_only=True)
    with psycopg.connect(dsn, autocommit=True) as conn:
        conn.execute(
            """
            create schema private;
            grant usage on schema private to authenticated;
            create table private.orgs (
              id uuid primary key default gen_random_uuid(),
              name text not null
            );
            create table private.org_members (
              user_id uuid not null references auth.users (id),
              org_id uuid not null references private.orgs (id)
            );
            create function private.my_org_ids() returns setof uuid
            language sql stable security definer set search_path = ''
            as $$ select org_id from private.org_members where user_id = auth.uid() $$;

            -- SAFE
            create table public.boards (
              id uuid primary key default gen_random_uuid(),
              org_id uuid not null references private.orgs (id),
              title text not null
            );
            alter table public.boards enable row level security;
            create policy "members read boards" on public.boards for select to authenticated
              using (org_id in (select private.my_org_ids()));

            -- VULN
            create table public.cards (
              id uuid primary key default gen_random_uuid(),
              org_id uuid not null references private.orgs (id),
              title text not null
            );
            alter table public.cards enable row level security;
            create policy "anyone logged in reads cards" on public.cards for select to authenticated
              using (true);
            """
        )
    report = run_audit(dsn, AuditConfig(), probe=True)
    assert _found(report, probe=True) == {("probe-cross-tenant-read", "public.cards", "high")}
    assert report.probe.tenancy.startswith("tenants in private.orgs")
    assert set(report.probe.probed) == {"public.boards", "public.cards"}
    assert report.probe.skipped == ()

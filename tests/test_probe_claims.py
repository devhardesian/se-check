"""JWT claims the probe infers from what policies and functions read."""

from __future__ import annotations

import pytest
from factories import catalog, function, policy

from se_check.config import AuditConfig
from se_check.probe.claims import claim_paths, describe_paths, inferred_claims


@pytest.mark.parametrize(
    ("sql", "paths"),
    [
        # As Postgres deparses policies: parentheses and ::text casts.
        (
            "(tenant_id = (((auth.jwt() -> 'user_metadata'::text) ->> 'tenant_id'::text))::uuid)",
            {("user_metadata", "tenant_id")},
        ),
        # The (select auth.jwt()) idiom, deparsed with an alias.
        (
            "(org_id = ((( SELECT auth.jwt() AS jwt) -> 'app_metadata'::text) ->> 'org_id'))",
            {("app_metadata", "org_id")},
        ),
        # Function bodies, as written.
        ("select auth.jwt()->'app_metadata'->>'team_id'", {("app_metadata", "team_id")}),
        # PostgREST's setting, and a path operator.
        (
            "(current_setting('request.jwt.claims'::text, true))::jsonb #>> "
            "'{app_metadata,tenant_id}'::text[]",
            {("app_metadata", "tenant_id")},
        ),
        # auth.users columns mirror the JWT's metadata.
        (
            "select (raw_user_meta_data ->> 'tenant_id')::uuid from auth.users",
            {("user_metadata", "tenant_id")},
        ),
        ("new.raw_app_meta_data -> 'org_id'", {("app_metadata", "org_id")}),
        ("auth.jwt() ->> 'role'", {("role",)}),
        ("auth.uid() is not null", set()),
        ("auth.jwt() is not null", set()),
    ],
)
def test_claim_paths(sql, paths):
    assert claim_paths(sql) == paths


def test_only_tenant_claims_are_inferred():
    cat = catalog(
        policies=[
            policy("a", using="tenant_id = ((auth.jwt() -> 'app_metadata') ->> 'tenant_id')"),
            policy("b", using="(auth.jwt() -> 'tenant_ids') ? tenant_id::text"),
            policy("c", using="(auth.jwt() ->> 'role') = 'admin'"),  # never given away
        ],
        functions=[function("f", body="select raw_user_meta_data ->> 'org_id'")],
    )
    template = inferred_claims(cat, AuditConfig())
    assert template == {
        "app_metadata": {"tenant_id": "{tenant}"},
        "tenant_ids": ["{tenant}"],
        "user_metadata": {"org_id": "{tenant}"},
    }
    assert describe_paths(template) == [
        "app_metadata.tenant_id",
        "tenant_ids",
        "user_metadata.org_id",
    ]


def test_configured_tenant_columns_count():
    cat = catalog(policies=[policy("a", using="clinic_id = (auth.jwt() ->> 'clinic_id')::uuid")])
    assert inferred_claims(cat, AuditConfig()) == {}
    assert inferred_claims(cat, AuditConfig(tenant_columns=("clinic_id",))) == {
        "clinic_id": "{tenant}"
    }


def test_comments_are_not_read():
    cat = catalog(functions=[function("f", body="-- auth.jwt() ->> 'tenant_id'\nselect 1")])
    assert inferred_claims(cat, AuditConfig()) == {}

"""Unit tests for the Supabase Auth checks."""

from __future__ import annotations

import pytest
from factories import catalog, function, run

from se_check.catalog import AuthUserTrigger
from se_check.checks.auth import AUTH_HOOK_EXPOSED, SIGNUP_TRIGGER_METADATA
from se_check.checks.functions import DEFINER_NO_CALLER_CHECK
from se_check.models import Severity

HOOK_BODY = "begin return event; end"

# --- auth-hook-exposed ------------------------------------------------------------------------


def test_hook_granted_to_auth_admin_and_callable_by_the_api_is_high():
    hook = function("custom_access_token_hook", arguments="event jsonb", auth_admin=True)
    [finding] = run(AUTH_HOOK_EXPOSED, catalog(functions=[hook]))
    assert finding.severity == Severity.HIGH
    assert finding.object == "public.custom_access_token_hook(event jsonb)"
    assert "from public, anon, authenticated" in finding.remediation


def test_hook_from_config_toml_is_recognized_without_the_grant():
    hook = function("access_token", arguments="event jsonb")
    cat = catalog(functions=[hook])
    assert run(AUTH_HOOK_EXPOSED, cat) == []
    assert len(run(AUTH_HOOK_EXPOSED, cat, auth_hooks=("public.access_token",))) == 1


def test_security_invoker_hook_is_medium():
    hook = function("hook", definer=False, auth_admin=True)
    assert [f.severity for f in run(AUTH_HOOK_EXPOSED, catalog(functions=[hook]))] == [
        Severity.MEDIUM
    ]


@pytest.mark.parametrize(
    "hook",
    [
        function("hook", auth_admin=True, executable_by=frozenset()),
        function("hook", auth_admin=True, schema="private"),
    ],
    ids=["revoked", "not-exposed"],
)
def test_hooks_the_api_cannot_reach_are_quiet(hook):
    assert run(AUTH_HOOK_EXPOSED, catalog(functions=[hook])) == []


def test_hooks_are_not_reported_twice():
    hook = function("custom_access_token_hook", body=HOOK_BODY, auth_admin=True)
    cat = catalog(functions=[hook])
    assert run(DEFINER_NO_CALLER_CHECK, cat) == []
    assert len(run(AUTH_HOOK_EXPOSED, cat)) == 1


# --- signup-trigger-metadata ------------------------------------------------------------------


def _signup(body: str, *, on_update: bool = False):
    return catalog(
        functions=[function("handle_new_user", body=body, is_trigger=True)],
        triggers=[
            AuthUserTrigger("on_auth_user_created", "public", "handle_new_user", True, on_update)
        ],
    )


def test_role_from_metadata_is_high():
    body = (
        "begin insert into public.profiles (id, role) values "
        "(new.id, new.raw_user_meta_data ->> 'role'); return new; end"
    )
    [finding] = run(SIGNUP_TRIGGER_METADATA, _signup(body))
    assert finding.severity == Severity.HIGH
    assert finding.object == "public.handle_new_user()"
    assert finding.evidence["metadata_keys"] == "role"
    assert "signs up" in finding.detail


def test_tenant_column_from_metadata_is_high():
    body = "select (new.raw_user_meta_data->>'tenant_id')::uuid"
    [finding] = run(SIGNUP_TRIGGER_METADATA, _signup(body))
    assert finding.evidence["metadata_keys"] == "tenant_id"


def test_configured_tenant_column_counts_too():
    body = "select new.raw_user_meta_data ->> 'clinic_id'"
    assert run(SIGNUP_TRIGGER_METADATA, _signup(body)) == []
    assert len(run(SIGNUP_TRIGGER_METADATA, _signup(body), tenant_columns=("clinic_id",))) == 1


def test_update_triggers_say_so():
    body = "select new.raw_user_meta_data ->> 'is_admin'"
    [finding] = run(SIGNUP_TRIGGER_METADATA, _signup(body, on_update=True))
    assert "signs up and updates their account" in finding.detail


@pytest.mark.parametrize(
    "body",
    [
        "insert into profiles (id, full_name, avatar_url) values (new.id, "
        "new.raw_user_meta_data ->> 'full_name', new.raw_user_meta_data ->> 'avatar_url')",
        "select new.raw_app_meta_data ->> 'role'",  # app_metadata: only the service role writes it
        "-- never: new.raw_user_meta_data ->> 'role'\nselect 1",
    ],
    ids=["harmless-keys", "app-metadata", "comment"],
)
def test_harmless_triggers_are_quiet(body):
    assert run(SIGNUP_TRIGGER_METADATA, _signup(body)) == []


def test_trigger_whose_function_is_unknown_is_skipped():
    cat = catalog(triggers=[AuthUserTrigger("t", "elsewhere", "fn")])
    assert run(SIGNUP_TRIGGER_METADATA, cat) == []

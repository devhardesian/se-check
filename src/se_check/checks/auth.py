"""Where the database meets Supabase Auth: hook functions and triggers on auth.users."""

from __future__ import annotations

import re
from collections.abc import Iterator

from se_check.catalog import Catalog
from se_check.checks.base import Check, strip_sql_comments
from se_check.checks.functions import api_callers, is_auth_hook, sql_name
from se_check.config import PRIVILEGED_NAMES, AuditConfig
from se_check.models import Finding, Severity


def _auth_hook_exposed(catalog: Catalog, config: AuditConfig) -> Iterator[Finding]:
    for function in catalog.functions:
        if not is_auth_hook(function, config):
            continue
        callers = api_callers(function, catalog, config)
        if not callers:
            continue
        yield Finding(
            check=AUTH_HOOK_EXPOSED.id,
            severity=Severity.HIGH if function.security_definer else Severity.MEDIUM,
            object=function.signature,
            title="Auth hook callable through the API",
            detail=(
                "Supabase Auth calls this function as a hook, but "
                f"{', '.join(callers)} can call it too, at /rest/v1/rpc/{function.name}, with "
                "any input they like: for an access-token hook, any user id, to read the claims "
                "it would issue for that user. Postgres lets everyone execute new functions "
                "unless the grant is revoked, and Supabase grants them to the API roles as well."
            ),
            remediation=(
                f"revoke execute on function {sql_name(function)} from public, "
                f"{', '.join(callers)};\n"
                "-- Supabase Auth keeps working: it calls the hook as supabase_auth_admin"
            ),
            evidence={"callable_by": ", ".join(callers)},
        )


AUTH_HOOK_EXPOSED = Check(
    id="auth-hook-exposed",
    title="Auth hooks callable through the API",
    description=(
        "Functions Supabase Auth calls as hooks (granted to supabase_auth_admin, or set up in "
        "supabase/config.toml) that anon or authenticated can also call via /rpc."
    ),
    run=_auth_hook_exposed,
)


# Metadata keys that must never decide privileges; the tenant columns are added at run time.
_METADATA_KEY = re.compile(r"user_meta_?data\s*->>?\s*'([A-Za-z0-9_]+)'", re.IGNORECASE)


def _signup_trigger_metadata(catalog: Catalog, config: AuditConfig) -> Iterator[Finding]:
    privileged = {key.lower() for key in (*PRIVILEGED_NAMES, *config.tenant_columns)}
    for trigger in catalog.auth_user_triggers:
        function = catalog.function(trigger.function_schema, trigger.function_name)
        if function is None or function.body is None:
            continue
        keys = sorted(
            {
                match.group(1)
                for match in _METADATA_KEY.finditer(strip_sql_comments(function.body))
                if match.group(1).lower() in privileged
            }
        )
        if not keys:
            continue
        when = (
            " and ".join(
                event
                for event, fires in (
                    ("signs up", trigger.on_insert),
                    ("updates their account", trigger.on_update),
                )
                if fires
            )
            or "changes"
        )
        listed = ", ".join(f"`{key}`" for key in keys)
        yield Finding(
            check=SIGNUP_TRIGGER_METADATA.id,
            severity=Severity.HIGH,
            object=function.signature,
            title=f"Trigger on auth.users takes {', '.join(keys)} from user_metadata",
            detail=(
                f'Trigger "{trigger.name}" runs whenever a user {when}, and reads {listed} from '
                "user_metadata, which the user writes themselves, e.g. "
                "`supabase.auth.signUp({ options: { data: { role: 'admin' } } })`. If the value "
                "ends up in a column your policies trust, anyone can make themselves an admin or "
                "join any tenant."
            ),
            remediation=(
                "Give new users fixed, unprivileged defaults (role 'member', no tenant) and "
                "assign roles and tenants server-side: invitations, admin actions or the service "
                "role. If you need data from the client at signup, take only harmless fields "
                "such as full_name or avatar_url.\n"
                f"-- the trigger function: {sql_name(function)}"
            ),
            evidence={"trigger": trigger.name, "metadata_keys": ", ".join(keys)},
        )


SIGNUP_TRIGGER_METADATA = Check(
    id="signup-trigger-metadata",
    title="Signup triggers that trust user_metadata",
    description=(
        "Triggers on auth.users (the usual handle_new_user) that copy a role, an admin flag, a "
        "plan or a tenant id out of user_metadata, which users set themselves at signup."
    ),
    run=_signup_trigger_metadata,
)

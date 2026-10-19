"""SECURITY DEFINER functions: they run with their owner's rights and bypass RLS."""

from __future__ import annotations

import re
from collections.abc import Iterator

from se_check.catalog import Catalog, Function
from se_check.checks.base import Check, calls, qualified, strip_sql_comments
from se_check.config import AuditConfig
from se_check.models import Finding, Severity

# Ways a function body can find out who is calling.
_CALLER_IDENTITY = re.compile(
    r"\bauth\s*\.\s*(?:uid|jwt|role|email)\s*\(|request\.jwt", re.IGNORECASE
)


def caller_aware_functions(catalog: Catalog, guard_functions: tuple[str, ...] = ()) -> set[str]:
    """Names of the functions that read the caller's identity, directly or through others.

    A project's permission helper (e.g. `has_permission()` reading `auth.uid()`) is found
    this way, so functions that call it count as checking the caller without configuration.
    `guard_functions` covers helpers whose source se-check cannot read.
    """
    bodies = [(fn.name, strip_sql_comments(fn.body)) for fn in catalog.functions if fn.body]
    aware = {name for name, body in bodies if _CALLER_IDENTITY.search(body)}
    aware.update(guard_functions)
    while True:
        found = {
            name
            for name, body in bodies
            if name not in aware and any(calls(helper, body) for helper in aware)
        }
        if not found:
            return aware
        aware |= found


def checks_caller(body: str, caller_aware: set[str] | tuple[str, ...] = ()) -> bool:
    code = strip_sql_comments(body)
    if _CALLER_IDENTITY.search(code):
        return True
    return any(calls(helper, code) for helper in caller_aware)


def sql_name(function: Function) -> str:
    return f"{qualified(function.schema, function.name)}({function.arguments})"


def is_auth_hook(function: Function, config: AuditConfig) -> bool:
    """Supabase Auth calls it: granted to supabase_auth_admin, or set up in config.toml."""
    return function.granted_to_auth_admin or function.qualified_name in config.auth_hooks


def api_callers(function: Function, catalog: Catalog, config: AuditConfig) -> list[str]:
    """API roles that can call the function through the Data API (`/rpc`)."""
    if function.is_trigger or function.schema not in config.schemas:
        return []
    return [role for role in catalog.api_roles if role in function.executable_by]


def _definer_no_caller_check(catalog: Catalog, config: AuditConfig) -> Iterator[Finding]:
    caller_aware = caller_aware_functions(catalog, config.guard_functions)
    for function in catalog.functions:
        # Auth hooks get their own, more precise finding (auth-hook-exposed).
        if not function.security_definer or function.body is None or is_auth_hook(function, config):
            continue
        callers = api_callers(function, catalog, config)
        if not callers or checks_caller(function.body, caller_aware):
            continue
        yield Finding(
            check=DEFINER_NO_CALLER_CHECK.id,
            severity=Severity.HIGH,
            object=function.signature,
            title="SECURITY DEFINER function callable through the API without checking the caller",
            detail=(
                "It runs with its owner's privileges, so RLS does not apply inside it, and "
                f"{', '.join(callers)} can call it at /rest/v1/rpc/{function.name}. Neither its "
                "body nor the functions it calls look at who is calling (auth.uid(), "
                "auth.jwt(), ...)."
            ),
            remediation=(
                "Check the caller first, e.g. `if not has_permission(...) then raise exception "
                "'forbidden'; end if;`, or make it SECURITY INVOKER if it doesn't need elevated "
                "rights, or take it off the API:\n"
                f"revoke execute on function {sql_name(function)} from public, "
                f"{', '.join(callers)};\n"
                "-- if it does check the caller through a helper se-check cannot read, "
                "name the helper with --guard"
            ),
            evidence={"callable_by": ", ".join(callers)},
        )


DEFINER_NO_CALLER_CHECK = Check(
    id="definer-no-caller-check",
    title="SECURITY DEFINER functions that don't check the caller",
    description=(
        "SECURITY DEFINER functions in the exposed schemas that API roles can call and that "
        "never read the caller's identity (auth.uid(), auth.jwt(), ...), neither directly nor "
        "through the functions they call."
    ),
    run=_definer_no_caller_check,
)


def _definer_search_path(catalog: Catalog, config: AuditConfig) -> Iterator[Finding]:
    for function in catalog.functions:
        if not function.security_definer or function.pins_search_path:
            continue
        exposed = bool(api_callers(function, catalog, config))
        yield Finding(
            check=DEFINER_SEARCH_PATH.id,
            severity=Severity.MEDIUM if exposed else Severity.LOW,
            object=function.signature,
            title="SECURITY DEFINER function without a fixed search_path",
            detail=(
                "It runs with its owner's privileges but resolves unqualified names through the "
                "caller's search_path, so whoever can create objects in a schema on that path "
                "can swap in their own tables, functions or operators."
                + (" It is callable through the API." if exposed else "")
            ),
            remediation=(
                f"alter function {sql_name(function)} set search_path = '';\n"
                "-- then schema-qualify every name in the body (public.my_table, auth.uid(), ...)"
            ),
        )


DEFINER_SEARCH_PATH = Check(
    id="definer-search-path",
    title="SECURITY DEFINER functions with a mutable search_path",
    description=(
        "SECURITY DEFINER functions that don't pin search_path. Medium when the API can call "
        "them, low otherwise."
    ),
    run=_definer_search_path,
    max_severity=Severity.MEDIUM,
)

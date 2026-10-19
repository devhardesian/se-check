"""Policies that don't restrict anything, or that trust data the user controls."""

from __future__ import annotations

import re
from collections.abc import Iterator

from se_check.catalog import Catalog, Policy, Table
from se_check.checks.base import Check, calls, qualified, quote_ident, strip_sql_comments, truncate
from se_check.config import AuditConfig
from se_check.models import Finding, Severity

ALWAYS_TRUE = "always-true"
ANY_LOGGED_IN = "any-logged-in"
CHECK_ONLY = "check-only"
"""UPDATE policy whose USING is fine but whose WITH CHECK accepts anything."""

_ALWAYS_TRUE_FORMS = frozenset({"true", "1=1"})

# How Postgres deparses the usual "the user is logged in" conditions, whitespace removed.
_ANY_LOGGED_IN_FORMS = frozenset(
    {
        "auth.uid()isnotnull",
        "(selectauth.uid()asuid)isnotnull",
        "auth.role()='authenticated'::text",
        "(selectauth.role()asrole)='authenticated'::text",
        "(auth.jwt()->>'role'::text)='authenticated'::text",
    }
)

_VERBS = {"SELECT": "read", "INSERT": "inserted", "UPDATE": "updated", "DELETE": "deleted"}


def classify_expression(expression: str | None) -> str | None:
    """Whether a deparsed policy expression lets every row through.

    Returns ALWAYS_TRUE, ANY_LOGGED_IN (true for every logged-in user) or None.
    """
    if expression is None:
        return None
    normalized = _strip_outer_parens(re.sub(r"\s+", "", expression.lower()))
    if normalized in _ALWAYS_TRUE_FORMS:
        return ALWAYS_TRUE
    if normalized in _ANY_LOGGED_IN_FORMS:
        return ANY_LOGGED_IN
    return None


def _strip_outer_parens(text: str) -> str:
    while text.startswith("(") and _matching_paren(text) == len(text) - 1:
        text = text[1:-1]
    return text


def _matching_paren(text: str) -> int:
    depth = 0
    for i, char in enumerate(text):
        if char == "(":
            depth += 1
        elif char == ")":
            depth -= 1
            if depth == 0:
                return i
    return -1


def _loose_commands(policy: Policy, table: Table, roles: list[str]) -> dict[str, str]:
    """Commands this policy opens to every row, mapped to how it opens them."""
    opened: dict[str, str] = {}
    for command in policy.commands:
        if command == "INSERT":
            kind = classify_expression(policy.effective_check)
        else:
            kind = classify_expression(policy.using)
            if command == "UPDATE" and kind is None and classify_expression(policy.effective_check):
                kind = CHECK_ONLY
        # A policy only matters for roles that hold the privilege in the first place.
        if kind and any(table.has_privilege(role, command) for role in roles):
            opened[command] = kind
    return opened


def _severity(command: str, kind: str, tenant_scoped: bool) -> Severity:
    if command == "SELECT":
        return Severity.HIGH if tenant_scoped else Severity.LOW
    if command == "INSERT":
        return Severity.HIGH if tenant_scoped else Severity.MEDIUM
    if kind == CHECK_ONLY:
        return Severity.MEDIUM
    return Severity.HIGH


def _join(words: list[str]) -> str:
    return words[0] if len(words) == 1 else ", ".join(words[:-1]) + " or " + words[-1]


def _policy_evidence(policy: Policy) -> dict[str, str]:
    evidence = {
        "policy": policy.name,
        "command": policy.command,
        "roles": ", ".join(policy.roles),
    }
    if policy.using is not None:
        evidence["using"] = truncate(policy.using)
    if policy.with_check is not None:
        evidence["with_check"] = truncate(policy.with_check)
    return evidence


def _permissive_policy(catalog: Catalog, config: AuditConfig) -> Iterator[Finding]:
    for policy in catalog.policies:
        if not policy.permissive:  # a restrictive `true` narrows nothing, but opens nothing either
            continue
        table = catalog.table(policy.schema, policy.table)
        roles = policy.applies_to(catalog.api_roles)
        if table is None or not roles:
            continue
        opened = _loose_commands(policy, table, roles)
        if not opened:
            continue

        tenant_column = next((c for c in table.columns if c in config.tenant_columns), None)
        severity = max(
            _severity(cmd, kind, tenant_column is not None) for cmd, kind in opened.items()
        )
        kinds = set(opened.values())

        detail = []
        if ALWAYS_TRUE in kinds:
            detail.append("Its condition is always true.")
        if ANY_LOGGED_IN in kinds:
            detail.append(
                "Its condition only checks that the user is logged in, so every account passes it."
            )
        if CHECK_ONLY in kinds:
            detail.append(
                "USING limits which rows can be updated, but WITH CHECK accepts any new values, "
                "so rows can be rewritten freely (e.g. moved to another tenant) unless a SELECT "
                "policy also constrains the new row."
            )
        detail.append(f"It applies to: {', '.join(roles)}.")
        if tenant_column:
            detail.append(
                f"The table has a `{tenant_column}` column, so users of one tenant reach the "
                "rows of every other tenant."
            )
        elif set(opened) == {"SELECT"}:
            detail.append(
                "Fine for public reference data (plans, countries, ...); otherwise tie the rows "
                "to the caller."
            )
        elif set(opened) == {"INSERT"}:
            detail.append("Fine for a public form; otherwise require ownership of the new rows.")

        clauses = []
        if any(cmd != "INSERT" and kind != CHECK_ONLY for cmd, kind in opened.items()):
            clauses.append("using (<condition>)")
        if "INSERT" in opened or CHECK_ONLY in kinds:
            clauses.append("with check (<condition>)")
        example = (
            f"{tenant_column} in (select <function returning the caller's tenant ids>())"
            if tenant_column
            else "user_id = (select auth.uid())"
        )
        remediation = (
            f"alter policy {quote_ident(policy.name)} on {qualified(policy.schema, policy.table)} "
            f"{' '.join(clauses)};\n-- where <condition> ties rows to the caller, e.g. {example}"
        )

        yield Finding(
            check=PERMISSIVE_POLICY.id,
            severity=severity,
            object=policy.table_name,
            title=(
                f'Policy "{policy.name}" does not restrict which rows can be '
                f"{_join([_VERBS[c] for c in opened])}"
            ),
            detail=" ".join(detail),
            remediation=remediation,
            evidence=_policy_evidence(policy),
        )


PERMISSIVE_POLICY = Check(
    id="permissive-policy",
    title="Policies that let every row through",
    description=(
        "Permissive policies whose condition is always true, or only checks that the user is "
        "logged in. High on tenant-scoped tables and for UPDATE/DELETE; low for read-only "
        "access to tables that look like public reference data."
    ),
    run=_permissive_policy,
)


# `user_metadata` in the JWT, `raw_user_meta_data` in auth.users. `app_metadata` is safe.
_USER_METADATA = re.compile(r"user_meta_?data", re.IGNORECASE)

_USER_METADATA_DETAIL = (
    "`user_metadata` (`auth.users.raw_user_meta_data`) can be changed by the user themselves "
    "with `supabase.auth.updateUser()`: anyone can write another tenant's id or an admin role "
    "there and pass this check."
)
_USER_METADATA_FIX = (
    "Read authorization data from a table users cannot write (e.g. a memberships table) or "
    "from `app_metadata`, which only the service role can change."
)


def _mentions_user_metadata(sql: str | None) -> bool:
    return sql is not None and _USER_METADATA.search(sql) is not None


def _user_metadata_auth(catalog: Catalog, config: AuditConfig) -> Iterator[Finding]:
    for policy in catalog.policies:
        if _mentions_user_metadata(policy.using) or _mentions_user_metadata(policy.with_check):
            yield Finding(
                check=USER_METADATA_AUTH.id,
                severity=Severity.HIGH,
                object=policy.table_name,
                title=f'Policy "{policy.name}" trusts user_metadata, which users can edit',
                detail=_USER_METADATA_DETAIL,
                remediation=_USER_METADATA_FIX,
                evidence=_policy_evidence(policy),
            )

    for function in catalog.functions:
        if function.body is None or not _mentions_user_metadata(strip_sql_comments(function.body)):
            continue
        used_by = [
            policy
            for policy in catalog.policies
            if any(
                expr and calls(function.name, expr) for expr in (policy.using, policy.with_check)
            )
        ]
        if not used_by:
            continue
        policies = "; ".join(f'{p.table_name}: "{p.name}"' for p in used_by)
        yield Finding(
            check=USER_METADATA_AUTH.id,
            severity=Severity.HIGH,
            object=function.signature,
            title=f"{function.name}() reads user_metadata and RLS policies rely on it",
            detail=f"{_USER_METADATA_DETAIL} Policies using it: {policies}.",
            remediation=_USER_METADATA_FIX,
            evidence={"policies": policies},
        )


USER_METADATA_AUTH = Check(
    id="user-metadata-auth",
    title="Authorization based on user_metadata",
    description=(
        "Policies, and functions called by policies, that read user_metadata: users can edit "
        "it themselves, so it must never decide tenant or role."
    ),
    run=_user_metadata_auth,
)

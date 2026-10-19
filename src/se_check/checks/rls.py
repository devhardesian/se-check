"""Tables reachable through the API without Row Level Security."""

from __future__ import annotations

from collections.abc import Iterator

from se_check.catalog import Catalog
from se_check.checks.base import Check, format_privileges, qualified
from se_check.config import AuditConfig
from se_check.models import Finding, Severity


def _rls_disabled(catalog: Catalog, config: AuditConfig) -> Iterator[Finding]:
    for table in catalog.tables:
        if table.rls_enabled:
            continue
        access = {role: privs for role, privs in table.privileges.items() if privs}
        remediation = (
            f"alter table {qualified(table.schema, table.name)} enable row level security;\n"
            "-- then add policies for the access you actually want: "
            "with RLS on and no policies, the API sees no rows."
        )
        if access:
            grants = "; ".join(
                f"{role}: {format_privileges(privs)}" for role, privs in sorted(access.items())
            )
            yield Finding(
                check=RLS_DISABLED.id,
                severity=Severity.CRITICAL,
                object=table.qualified_name,
                title="Row Level Security is disabled on a table the API can reach",
                detail=(
                    "Without RLS these grants apply to every row of the table, whatever "
                    f"tenant or user it belongs to ({grants}). Anyone holding a key for "
                    "these roles can use them directly through the Data API."
                ),
                remediation=remediation,
                evidence={"grants": grants},
            )
        else:
            yield Finding(
                check=RLS_DISABLED.id,
                severity=Severity.LOW,
                object=table.qualified_name,
                title="Row Level Security is disabled (no API grants on this table today)",
                detail=(
                    "No API role can reach the table now, but a single future GRANT would "
                    "expose every row at once. Enabling RLS keeps it closed by default."
                ),
                remediation=remediation,
            )


RLS_DISABLED = Check(
    id="rls-disabled",
    title="Tables without Row Level Security",
    description=(
        "Tables in the exposed schemas with RLS turned off. Critical when an API role has "
        "grants on them, since every row is then readable or writable through the Data API."
    ),
    run=_rls_disabled,
    max_severity=Severity.CRITICAL,
)

"""The registry of checks."""

from __future__ import annotations

from collections.abc import Iterable

from se_check.catalog import Catalog
from se_check.checks.auth import AUTH_HOOK_EXPOSED, SIGNUP_TRIGGER_METADATA
from se_check.checks.base import Check
from se_check.checks.functions import DEFINER_NO_CALLER_CHECK, DEFINER_SEARCH_PATH
from se_check.checks.policies import PERMISSIVE_POLICY, USER_METADATA_AUTH
from se_check.checks.rls import RLS_DISABLED
from se_check.config import AuditConfig
from se_check.models import Finding

ALL_CHECKS: tuple[Check, ...] = (
    RLS_DISABLED,
    PERMISSIVE_POLICY,
    USER_METADATA_AUTH,
    AUTH_HOOK_EXPOSED,
    SIGNUP_TRIGGER_METADATA,
    DEFINER_NO_CALLER_CHECK,
    DEFINER_SEARCH_PATH,
)


def select_checks(ids: Iterable[str] | None = None) -> tuple[Check, ...]:
    """The checks with the given ids, or all of them. Unknown ids raise ValueError."""
    if not ids:
        return ALL_CHECKS
    by_id = {check.id: check for check in ALL_CHECKS}
    wanted = list(dict.fromkeys(ids))
    unknown = [check_id for check_id in wanted if check_id not in by_id]
    if unknown:
        raise ValueError(f"unknown check(s): {', '.join(unknown)} (available: {', '.join(by_id)})")
    return tuple(by_id[check_id] for check_id in wanted)


def run_checks(
    catalog: Catalog, config: AuditConfig, ids: Iterable[str] | None = None
) -> list[Finding]:
    """Run the checks and return their findings, most severe first."""
    findings = [finding for check in select_checks(ids) for finding in check.run(catalog, config)]
    findings.sort(key=lambda f: (-f.severity, f.check, f.object))
    return findings


__all__ = ["ALL_CHECKS", "Check", "run_checks", "select_checks"]

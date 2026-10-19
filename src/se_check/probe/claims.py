"""The JWT claims a real user of the app carries, inferred from what the policies read.

A persona whose JWT lacks the claim a policy compares with the tenant is turned away by every
policy, honest or not: the probe would see nothing. So the claims the policies and their
helpers read, and that name a tenant (`auth.jwt() -> 'app_metadata' ->> 'tenant_id'`), are
filled with the persona's tenant, as the app would fill them. The same goes for
`raw_user_meta_data` / `raw_app_meta_data` read from auth.users.
"""

from __future__ import annotations

import re
from typing import Any

from se_check.catalog import Catalog
from se_check.checks.base import strip_sql_comments
from se_check.config import AuditConfig

TENANT = "{tenant}"
"""Placeholder for the persona's tenant id, filled in by the executor."""

# Where claims come from: the JWT, as functions or as PostgREST's setting, or the metadata
# columns of auth.users (which the JWT's app_metadata and user_metadata mirror).
_HEAD = re.compile(
    r"auth\s*\.\s*jwt\s*\(\s*\)"
    r"|current_setting\s*\(\s*'request\.jwt\.claims'(?:\s*::\s*text)?\s*,\s*true\s*\)"
    r"|\braw_(user|app)_meta_?data\b",
    re.IGNORECASE,
)
# One `-> 'key'`, `->> 'key'` or `#>> '{a,b}'`, past the parentheses, casts and `AS jwt`
# aliases that Postgres puts around them when it deparses a policy.
_STEP = re.compile(
    r"(?:\s|\)|::\s*\w+(?:\[\])?|\bas\s+\w+)*"
    r"(->>?|#>>?)\s*'([^']*)'(?:\s*::\s*text(?:\[\])?)?",
    re.IGNORECASE,
)


def claim_paths(sql: str) -> set[tuple[str, ...]]:
    """The claim paths an expression or function body reads, e.g. ('app_metadata', 'org_id')."""
    paths: set[tuple[str, ...]] = set()
    for head in _HEAD.finditer(sql):
        path = [f"{head.group(1).lower()}_metadata"] if head.group(1) else []
        position = head.end()
        while step := _STEP.match(sql, position):
            operator, key = step.group(1), step.group(2)
            if operator.startswith("#"):
                path.extend(part.strip().strip('"') for part in key.strip("{}").split(","))
            else:
                path.append(key)
            position = step.end()
        if path:
            paths.add(tuple(path))
    return paths


def inferred_claims(catalog: Catalog, config: AuditConfig) -> dict[str, Any]:
    """A claims template: tenant-naming claims the policies read, holding TENANT.

    A key named like a tenant column holds the tenant id; its plural (`tenant_ids`) a list
    holding it. Other claims (roles, flags) are left out: a persona gets no privilege the probe
    did not mean to give.
    """
    sources = [expr for p in catalog.policies for expr in (p.using, p.with_check) if expr]
    sources += [strip_sql_comments(f.body) for f in catalog.functions if f.body]
    paths = set().union(*(claim_paths(sql) for sql in sources)) if sources else set()

    template: dict[str, Any] = {}
    for path in sorted(paths):
        key = path[-1]
        if key in config.tenant_columns:
            value: Any = TENANT
        elif key.endswith("s") and key[:-1] in config.tenant_columns:
            value = [TENANT]
        else:
            continue
        node = template
        for part in path[:-1]:
            child = node.setdefault(part, {})
            if not isinstance(child, dict):
                break
            node = child
        else:
            node[key] = value
    return template


def describe_paths(template: dict[str, Any], prefix: str = "") -> list[str]:
    """`app_metadata.tenant_id`-style names of the claims a template sets."""
    names = []
    for key, value in template.items():
        name = f"{prefix}{key}"
        if isinstance(value, dict):
            names.extend(describe_paths(value, f"{name}."))
        else:
            names.append(name)
    return names

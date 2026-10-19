"""What the audit needs to know about the project that the catalog cannot tell it."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any

# Roles PostgREST switches to for anonymous and logged-in requests on Supabase.
DEFAULT_API_ROLES = ("anon", "authenticated")

# Column names that usually mean "this row belongs to a tenant".
DEFAULT_TENANT_COLUMNS = (
    "tenant_id",
    "org_id",
    "organization_id",
    "organisation_id",
    "team_id",
    "workspace_id",
    "company_id",
    "account_id",
)

# Names (metadata keys, columns) that decide privileges: users must never set them themselves.
PRIVILEGED_NAMES = (
    "role",
    "roles",
    "user_role",
    "app_role",
    "is_admin",
    "admin",
    "is_superuser",
    "superuser",
    "permissions",
    "plan",
    "tier",
)

# Schemas owned by Supabase, Postgres or common extensions: their functions are not project code.
# Schemas starting with `pg_` are skipped as well.
MANAGED_SCHEMAS = (
    "information_schema",
    "auth",
    "storage",
    "realtime",
    "_realtime",
    "extensions",
    "graphql",
    "graphql_public",
    "vault",
    "net",
    "pgsodium",
    "pgsodium_masks",
    "supabase_functions",
    "supabase_migrations",
    "cron",
    "pgbouncer",
    "_analytics",
    "pgtle",
    "topology",
    "tiger",
    "tiger_data",
)


@dataclass(frozen=True)
class AuditConfig:
    schemas: tuple[str, ...] = ("public",)
    """Schemas exposed through the Data API (PostgREST)."""

    api_roles: tuple[str, ...] = DEFAULT_API_ROLES
    """Roles that API requests run as."""

    tenant_columns: tuple[str, ...] = DEFAULT_TENANT_COLUMNS
    """Columns that mark a table as tenant-scoped."""

    guard_functions: tuple[str, ...] = ()
    """Project functions that check the caller (e.g. `has_permission`), besides `auth.*`."""

    auth_hooks: tuple[str, ...] = ()
    """`schema.function` names configured as Auth hooks in supabase/config.toml."""

    access_token_hook: str | None = None
    """`schema.function` of the custom access token hook in supabase/config.toml."""


@dataclass(frozen=True)
class ProbeConfig:
    """`[probe]` in se-check.toml: what the dynamic probe cannot work out from the catalog."""

    skip_tables: tuple[str, ...] = ()
    """`schema.table` names the probe leaves alone."""

    values: Mapping[str, Mapping[str, str]] = field(default_factory=dict)
    """`schema.table` -> column -> value for synthetic rows, as text Postgres casts to the type."""

    claims: Mapping[str, Any] = field(default_factory=dict)
    """Extra JWT claims for logged-in personas; the strings "{user}" and "{tenant}" become ids."""

    membership: str | None = None
    """SQL that makes %(user)s a member of %(tenant)s, when the catalog doesn't show how."""

    privilege_columns: tuple[str, ...] = ()
    """Columns users must not change on their own rows, besides the usual ones (role, plan...)."""

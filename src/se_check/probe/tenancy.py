"""Work out from the catalog how rows belong to tenants."""

from __future__ import annotations

from collections import Counter

from se_check.catalog import Catalog, Table
from se_check.config import AuditConfig
from se_check.probe.model import Tenancy

AUTH_USERS = "auth.users"


def infer_tenancy(catalog: Catalog, config: AuditConfig) -> Tenancy:
    """The tenant table, and the tables whose rows belong to a tenant.

    The tenant table is the one the tenant columns (`tenant_id`, `org_id`, ...) reference most.
    A table is tenant-scoped when it has a tenant column, or a NOT NULL foreign key to a
    tenant-scoped table (comments of a document belong to the document's tenant). Other tables
    with a NOT NULL reference to a user hold rows owned by that user (`notes.user_id`).
    """
    every = (*catalog.tables, *catalog.support_tables)
    tables = {table.qualified_name: table for table in every}
    references: Counter[tuple[str, str]] = Counter()
    for table in every:
        for fk in table.foreign_keys:
            if (
                len(fk.columns) == 1
                and fk.columns[0] in config.tenant_columns
                and fk.ref_name in tables
                and fk.ref_name != table.qualified_name
            ):
                references[(fk.ref_name, fk.ref_columns[0])] += 1

    tenant_table = tenant_key = None
    scoped: dict[str, str] = {}
    if references:
        (tenant_table, tenant_key), _ = min(references.items(), key=lambda kv: (-kv[1], kv[0]))
        scoped[tenant_table] = f"is the tenant table ({tenant_key})"

    for table in every:
        column = tenant_column(table, config)
        if column and table.qualified_name not in scoped:
            scoped[table.qualified_name] = column

    changed = True
    while changed:
        changed = False
        for table in every:
            if table.qualified_name in scoped:
                continue
            for fk in table.foreign_keys:
                if fk.ref_name in scoped and _not_null(table, fk.columns):
                    scoped[table.qualified_name] = f"{', '.join(fk.columns)} -> {fk.ref_name}"
                    changed = True
                    break

    user_scoped = {
        table.qualified_name: column
        for table in every
        if table.qualified_name not in scoped and (column := owner_column(table)) is not None
    }
    return Tenancy(
        tenant_table=tenant_table, tenant_key=tenant_key, scoped=scoped, user_scoped=user_scoped
    )


def user_columns(table: Table) -> list[str]:
    """Columns that reference a user (`auth.users.id`)."""
    return [
        fk.columns[0]
        for fk in table.foreign_keys
        if fk.ref_name == AUTH_USERS and fk.ref_columns == ("id",)
    ]


def owner_column(table: Table) -> str | None:
    """The NOT NULL column that says which user a row belongs to (`notes.user_id`)."""
    return next((c for c in user_columns(table) if _not_null(table, (c,))), None)


def is_identity_row(table: Table) -> bool:
    """Whether the primary key includes a user: one row per user (`profiles`), or per user and
    tenant (`memberships`). Such rows say who the user is, not just what they wrote."""
    return bool(set(user_columns(table)) & set(table.primary_key))


def tenant_column(table: Table, config: AuditConfig) -> str | None:
    return next((c for c in table.columns if c in config.tenant_columns), None)


def _not_null(table: Table, columns: tuple[str, ...]) -> bool:
    details = [table.column(name) for name in columns]
    return all(column is not None and column.not_null for column in details)

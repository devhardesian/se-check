"""Builders for hand-made catalogs and project folders, so most tests need no database."""

from __future__ import annotations

from pathlib import Path

from se_check.catalog import (
    PRIVILEGES,
    Catalog,
    Column,
    ForeignKey,
    Function,
    Policy,
    Table,
    TableTrigger,
)
from se_check.config import AuditConfig
from se_check.models import Finding

API_ROLES = ("anon", "authenticated")
ALL = frozenset(PRIVILEGES)


def table(
    name: str,
    *,
    rls: bool = True,
    columns: tuple[str, ...] = ("id",),
    privileges: dict[str, frozenset[str]] | None = None,
    schema: str = "public",
    details: tuple[Column, ...] | None = None,
    primary_key: tuple[str, ...] | None = None,
    foreign_keys: tuple[ForeignKey, ...] = (),
    triggers: tuple[TableTrigger, ...] = (),
) -> Table:
    """`details` describes the columns (for the probe); their names then replace `columns`."""
    if privileges is None:  # Supabase default: the API roles hold every privilege
        privileges = {role: ALL for role in API_ROLES}
    if details is not None:
        columns = tuple(c.name for c in details)
    if primary_key is None:
        primary_key = ("id",) if "id" in columns else ()
    return Table(
        schema=schema,
        name=name,
        rls_enabled=rls,
        columns=columns,
        privileges=privileges,
        column_details=details or (),
        primary_key=primary_key,
        foreign_keys=foreign_keys,
        triggers=triggers,
    )


# Short type names -> (pg_type.typname, pg_type.typcategory).
_TYPES = {
    "text": ("text", "S"),
    "varchar": ("varchar", "S"),
    "uuid": ("uuid", "U"),
    "jsonb": ("jsonb", "U"),
    "int2": ("int2", "N"),
    "int4": ("int4", "N"),
    "int8": ("int8", "N"),
    "numeric": ("numeric", "N"),
    "bool": ("bool", "B"),
    "timestamptz": ("timestamptz", "D"),
    "interval": ("interval", "T"),
    "inet": ("inet", "I"),
    "text[]": ("_text", "A"),
    "point": ("point", "G"),
}


def col(
    name: str,
    type_: str = "text",
    *,
    not_null: bool = False,
    default: bool = False,
    identity: str = "",
    generated: bool = False,
    labels: tuple[str, ...] = (),
    max_length: int | None = None,
) -> Column:
    base, category = _TYPES.get(type_, (type_, "E" if labels else "U"))
    return Column(
        name=name,
        type=type_,
        base_type=base,
        category=category,
        max_length=max_length,
        not_null=not_null,
        has_default=default or generated,
        identity=identity,
        generated=generated,
        enum_labels=labels,
    )


def fk(
    columns: str | tuple[str, ...], ref: str, ref_columns: tuple[str, ...] = ("id",)
) -> ForeignKey:
    columns = (columns,) if isinstance(columns, str) else columns
    ref_schema, ref_table = ref.split(".", 1)
    return ForeignKey(f"{'_'.join(columns)}_fkey", columns, ref_schema, ref_table, ref_columns)


def policy(
    table_name: str,
    *,
    name: str = "p",
    command: str = "SELECT",
    roles: tuple[str, ...] = ("authenticated",),
    using: str | None = None,
    with_check: str | None = None,
    permissive: bool = True,
) -> Policy:
    return Policy(
        schema="public",
        table=table_name,
        name=name,
        command=command,
        roles=roles,
        permissive=permissive,
        using=using,
        with_check=with_check,
    )


def function(
    name: str,
    *,
    body: str | None = "select 1",
    definer: bool = True,
    config: tuple[str, ...] = ('search_path=""',),
    executable_by: frozenset[str] = frozenset(API_ROLES),
    schema: str = "public",
    arguments: str = "",
    is_trigger: bool = False,
    auth_admin: bool = False,
) -> Function:
    return Function(
        schema=schema,
        name=name,
        arguments=arguments,
        language="plpgsql",
        security_definer=definer,
        config=config,
        body=body,
        is_trigger=is_trigger,
        executable_by=executable_by,
        granted_to_auth_admin=auth_admin,
    )


def catalog(
    *, tables=(), policies=(), functions=(), triggers=(), api_roles=API_ROLES, support=()
) -> Catalog:
    """`support`: tables of schemas the API does not expose."""
    return Catalog(
        server_version="16.2",
        api_roles=api_roles,
        tables=tuple(tables),
        policies=tuple(policies),
        functions=tuple(functions),
        auth_user_triggers=tuple(triggers),
        support_tables=tuple(support),
    )


def run(check, cat: Catalog, **config) -> list[Finding]:
    return list(check.run(cat, AuditConfig(**config)))


POOLER_URL = "postgresql://postgres.abcdefgh@aws-0-eu-west-1.pooler.supabase.com:5432/postgres"


def supabase_project(
    root: Path, config: str = "[db]\nport = 54322\n", pooler_url: str | None = None
) -> Path:
    """A folder laid out like a Supabase CLI project; `pooler_url` as left by `supabase link`."""
    (root / "supabase").mkdir(parents=True)
    (root / "supabase" / "config.toml").write_text(config)
    if pooler_url is not None:
        (root / "supabase" / ".temp").mkdir()
        (root / "supabase" / ".temp" / "pooler-url").write_text(pooler_url + "\n")
    return root

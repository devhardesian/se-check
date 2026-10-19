"""A read-only snapshot of the catalog objects the checks look at.

Checks are pure functions over a `Catalog`: they can be unit-tested without a database,
and the snapshot is loaded with a handful of catalog queries in one read-only transaction.
Only metadata is read, never table contents.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field

import psycopg

from se_check.config import MANAGED_SCHEMAS, AuditConfig

PRIVILEGES = ("SELECT", "INSERT", "UPDATE", "DELETE")


@dataclass(frozen=True)
class Column:
    """What the dynamic probe needs to make up a value for a column."""

    name: str
    type: str = "text"
    """As Postgres prints it, e.g. `character varying(20)`."""
    base_type: str = "text"
    """`pg_type.typname` of the type, or of a domain's base type: `uuid`, `int4`, `varchar`..."""
    category: str = "S"
    """`pg_type.typcategory`: S string, N numeric, B boolean, D date/time, A array, U user..."""
    max_length: int | None = None
    """For varchar(n) and char(n)."""
    not_null: bool = False
    has_default: bool = False
    identity: str = ""
    """`a` (GENERATED ALWAYS), `d` (BY DEFAULT) or empty."""
    generated: bool = False
    enum_labels: tuple[str, ...] = ()


@dataclass(frozen=True)
class ForeignKey:
    name: str
    columns: tuple[str, ...]
    ref_schema: str
    ref_table: str
    ref_columns: tuple[str, ...]

    @property
    def ref_name(self) -> str:
        return f"{self.ref_schema}.{self.ref_table}"


@dataclass(frozen=True)
class TableTrigger:
    name: str
    function_schema: str
    function_name: str


@dataclass(frozen=True)
class Table:
    schema: str
    name: str
    rls_enabled: bool
    columns: tuple[str, ...] = ()
    privileges: Mapping[str, frozenset[str]] = field(default_factory=dict)
    """API role -> privileges it holds on the table, directly or through PUBLIC."""
    column_details: tuple[Column, ...] = ()
    primary_key: tuple[str, ...] = ()
    foreign_keys: tuple[ForeignKey, ...] = ()
    triggers: tuple[TableTrigger, ...] = ()

    @property
    def qualified_name(self) -> str:
        return f"{self.schema}.{self.name}"

    def has_privilege(self, role: str, privilege: str) -> bool:
        return privilege in self.privileges.get(role, frozenset())

    def column(self, name: str) -> Column | None:
        return next((c for c in self.column_details if c.name == name), None)


@dataclass(frozen=True)
class Policy:
    schema: str
    table: str
    name: str
    command: str
    """ALL, SELECT, INSERT, UPDATE or DELETE."""
    roles: tuple[str, ...]
    permissive: bool = True
    using: str | None = None
    with_check: str | None = None

    @property
    def table_name(self) -> str:
        return f"{self.schema}.{self.table}"

    @property
    def commands(self) -> tuple[str, ...]:
        return PRIVILEGES if self.command == "ALL" else (self.command,)

    @property
    def effective_check(self) -> str | None:
        """Expression new rows must satisfy: Postgres reuses USING when WITH CHECK is absent."""
        return self.with_check if self.with_check is not None else self.using

    def applies_to(self, roles: Iterable[str]) -> list[str]:
        """The given roles this policy applies to (a policy `TO public` covers all of them)."""
        if "public" in self.roles:
            return list(roles)
        return [role for role in roles if role in self.roles]


@dataclass(frozen=True)
class Function:
    schema: str
    name: str
    arguments: str
    language: str
    security_definer: bool
    config: tuple[str, ...] = ()
    """`proconfig` entries, e.g. `search_path=""`."""
    body: str | None = None
    """Source of SQL and PL/pgSQL functions; None for other languages."""
    is_trigger: bool = False
    executable_by: frozenset[str] = frozenset()
    """API roles that can call it."""
    granted_to_auth_admin: bool = False
    """EXECUTE explicitly granted to supabase_auth_admin: Supabase Auth calls it as a hook."""

    @property
    def qualified_name(self) -> str:
        return f"{self.schema}.{self.name}"

    @property
    def signature(self) -> str:
        return f"{self.schema}.{self.name}({self.arguments})"

    @property
    def pins_search_path(self) -> bool:
        return any(setting.startswith("search_path=") for setting in self.config)


@dataclass(frozen=True)
class AuthUserTrigger:
    """A trigger on auth.users, e.g. the usual `handle_new_user` that fills a profile."""

    name: str
    function_schema: str
    function_name: str
    on_insert: bool = True
    on_update: bool = False


@dataclass(frozen=True)
class Catalog:
    server_version: str
    api_roles: tuple[str, ...]
    """Configured API roles that exist in this database."""
    tables: tuple[Table, ...] = ()
    policies: tuple[Policy, ...] = ()
    functions: tuple[Function, ...] = ()
    auth_user_triggers: tuple[AuthUserTrigger, ...] = ()
    support_tables: tuple[Table, ...] = ()
    """Tables of the project's other schemas (`private`, ...). The API cannot reach them, so the
    checks ignore them; the probe fills them when exposed rows point at them."""

    def table(self, schema: str, name: str) -> Table | None:
        return next((t for t in self.tables if t.schema == schema and t.name == name), None)

    def function(self, schema: str, name: str) -> Function | None:
        """The function with this name (the first overload, if there are several)."""
        return next((f for f in self.functions if f.schema == schema and f.name == name), None)


_TABLES = """
select n.nspname::text, c.relname::text, c.relrowsecurity,
       array(select a.attname::text from pg_catalog.pg_attribute a
             where a.attrelid = c.oid and a.attnum > 0 and not a.attisdropped
             order by a.attnum)
from pg_catalog.pg_class c
join pg_catalog.pg_namespace n on n.oid = c.relnamespace
where c.relkind in ('r', 'p') and not c.relispartition and n.nspname = any(%(schemas)s)
order by 1, 2
"""

# Column-level grants count too: SELECT on one column is enough to read rows.
_TABLE_PRIVILEGES = """
select n.nspname::text, c.relname::text, r.role, p.privilege
from pg_catalog.pg_class c
join pg_catalog.pg_namespace n on n.oid = c.relnamespace
cross join unnest(%(roles)s::text[]) as r(role)
cross join unnest(%(privileges)s::text[]) as p(privilege)
where c.relkind in ('r', 'p') and not c.relispartition and n.nspname = any(%(schemas)s)
  and case p.privilege
        when 'DELETE' then pg_catalog.has_table_privilege(r.role, c.oid, 'DELETE')
        else pg_catalog.has_any_column_privilege(r.role, c.oid, p.privilege)
      end
"""

# Domains count as their base type, so that a value can be made up for them.
_COLUMNS = """
select n.nspname::text, c.relname::text, a.attname::text,
       pg_catalog.format_type(a.atttypid, a.atttypmod),
       coalesce(bt.typname, t.typname)::text,
       coalesce(bt.typcategory, t.typcategory)::text,
       case when coalesce(bt.typname, t.typname) in ('varchar', 'bpchar')
            then nullif(greatest(case when t.typtype = 'd' then t.typtypmod
                                      else a.atttypmod end - 4, -1), -1) end,
       a.attnotnull or (t.typtype = 'd' and t.typnotnull),
       a.atthasdef,
       a.attidentity::text,
       a.attgenerated <> '',
       array(select e.enumlabel::text from pg_catalog.pg_enum e
             where e.enumtypid = coalesce(bt.oid, t.oid) order by e.enumsortorder)
from pg_catalog.pg_attribute a
join pg_catalog.pg_class c on c.oid = a.attrelid
join pg_catalog.pg_namespace n on n.oid = c.relnamespace
join pg_catalog.pg_type t on t.oid = a.atttypid
left join pg_catalog.pg_type bt on t.typtype = 'd' and bt.oid = t.typbasetype
where c.relkind in ('r', 'p') and not c.relispartition and n.nspname = any(%(schemas)s)
  and a.attnum > 0 and not a.attisdropped
order by 1, 2, a.attnum
"""

# Primary and foreign keys. Constraints cloned onto partitions (conparentid <> 0) are left out.
_KEYS = """
select n.nspname::text, c.relname::text, k.conname::text, k.contype::text,
       array(select a.attname::text
             from unnest(k.conkey) with ordinality as u(attnum, i)
             join pg_catalog.pg_attribute a on a.attrelid = k.conrelid and a.attnum = u.attnum
             order by u.i),
       rn.nspname::text, r.relname::text,
       array(select a.attname::text
             from unnest(k.confkey) with ordinality as u(attnum, i)
             join pg_catalog.pg_attribute a on a.attrelid = k.confrelid and a.attnum = u.attnum
             order by u.i)
from pg_catalog.pg_constraint k
join pg_catalog.pg_class c on c.oid = k.conrelid
join pg_catalog.pg_namespace n on n.oid = c.relnamespace
left join pg_catalog.pg_class r on r.oid = k.confrelid
left join pg_catalog.pg_namespace rn on rn.oid = r.relnamespace
where k.contype in ('p', 'f') and k.conparentid = 0
  and c.relkind in ('r', 'p') and not c.relispartition and n.nspname = any(%(schemas)s)
order by 1, 2, 3
"""

_TABLE_TRIGGERS = """
select n.nspname::text, c.relname::text, t.tgname::text, pn.nspname::text, p.proname::text
from pg_catalog.pg_trigger t
join pg_catalog.pg_class c on c.oid = t.tgrelid
join pg_catalog.pg_namespace n on n.oid = c.relnamespace
join pg_catalog.pg_proc p on p.oid = t.tgfoid
join pg_catalog.pg_namespace pn on pn.oid = p.pronamespace
where not t.tgisinternal
  and c.relkind in ('r', 'p') and not c.relispartition and n.nspname = any(%(schemas)s)
order by 1, 2, 3
"""

_POLICIES = """
select schemaname::text, tablename::text, policyname::text, cmd, roles::text[],
       permissive = 'PERMISSIVE', qual, with_check
from pg_catalog.pg_policies
where schemaname = any(%(schemas)s)
order by 1, 2, 3
"""

# Functions from every non-managed schema: policies often call helpers in a private schema.
# Functions that belong to an extension are skipped.
_FUNCTIONS = """
select n.nspname::text, p.proname::text,
       pg_catalog.pg_get_function_identity_arguments(p.oid),
       l.lanname::text,
       p.prosecdef,
       coalesce(p.proconfig, '{}')::text[],
       case when l.lanname in ('sql', 'plpgsql') then p.prosrc end,
       p.prorettype in ('pg_catalog.trigger'::pg_catalog.regtype,
                        'pg_catalog.event_trigger'::pg_catalog.regtype),
       array(select r.role from unnest(%(roles)s::text[]) as r(role)
             where pg_catalog.has_function_privilege(r.role, p.oid, 'EXECUTE')),
       coalesce((select bool_or(a.privilege_type = 'EXECUTE')
                 from pg_catalog.aclexplode(p.proacl) as a
                 where a.grantee = (select oid from pg_catalog.pg_roles
                                    where rolname = 'supabase_auth_admin')), false)
from pg_catalog.pg_proc p
join pg_catalog.pg_namespace n on n.oid = p.pronamespace
join pg_catalog.pg_language l on l.oid = p.prolang
where p.prokind = 'f'
  and n.nspname <> all(%(managed)s)
  and left(n.nspname, 3) <> 'pg_'
  and not exists (
    select from pg_catalog.pg_depend d
    where d.classid = 'pg_catalog.pg_proc'::pg_catalog.regclass
      and d.objid = p.oid and d.deptype = 'e'
  )
order by 1, 2, 3
"""

# tgtype bits: 4 = INSERT, 16 = UPDATE. to_regclass() is NULL when there is no auth.users.
_SUPPORT_SCHEMAS = """
select n.nspname::text from pg_catalog.pg_namespace n
where n.nspname <> all(%(managed)s) and n.nspname <> all(%(schemas)s)
  and left(n.nspname, 3) <> 'pg_'
order by 1
"""

_AUTH_USER_TRIGGERS = """
select t.tgname::text, n.nspname::text, p.proname::text,
       (t.tgtype & 4) <> 0, (t.tgtype & 16) <> 0
from pg_catalog.pg_trigger t
join pg_catalog.pg_proc p on p.oid = t.tgfoid
join pg_catalog.pg_namespace n on n.oid = p.pronamespace
where t.tgrelid = pg_catalog.to_regclass('auth.users') and not t.tgisinternal
order by 1
"""


def load_catalog(conn: psycopg.Connection, config: AuditConfig) -> Catalog:
    """Read the snapshot in a single transaction, so every check sees the same state."""
    with conn.transaction(), conn.cursor() as cur:
        # LOCAL keeps the setting inside this transaction, which matters behind a pooler.
        cur.execute("select pg_catalog.set_config('statement_timeout', '30s', true)")
        cur.execute("select pg_catalog.current_setting('server_version')")
        server_version = cur.fetchone()[0]

        cur.execute(
            "select rolname::text from pg_catalog.pg_roles where rolname = any(%s)",
            (list(config.api_roles),),
        )
        existing = {row[0] for row in cur.fetchall()}
        api_roles = tuple(role for role in config.api_roles if role in existing)

        params = {
            "schemas": list(config.schemas),
            "roles": list(api_roles),
            "privileges": list(PRIVILEGES),
            "managed": list(MANAGED_SCHEMAS),
        }

        tables = _load_tables(cur, params)
        # Other project schemas (e.g. `private`): the API can't reach their tables, but rows of
        # exposed tables point at them, and the probe has to fill them too.
        cur.execute(_SUPPORT_SCHEMAS, params)
        support_schemas = [row[0] for row in cur.fetchall()]
        support_tables = (
            _load_tables(cur, {**params, "schemas": support_schemas}) if support_schemas else ()
        )

        cur.execute(_POLICIES, params)
        policies = tuple(
            Policy(
                schema=schema,
                table=table,
                name=name,
                command=command,
                roles=tuple(roles),
                permissive=permissive,
                using=using,
                with_check=with_check,
            )
            for schema, table, name, command, roles, permissive, using, with_check in cur.fetchall()
        )

        cur.execute(_FUNCTIONS, params)
        functions = tuple(
            Function(
                schema=schema,
                name=name,
                arguments=arguments,
                language=language,
                security_definer=security_definer,
                config=tuple(fn_config),
                body=body,
                is_trigger=is_trigger,
                executable_by=frozenset(executable_by),
                granted_to_auth_admin=granted_to_auth_admin,
            )
            for (
                schema,
                name,
                arguments,
                language,
                security_definer,
                fn_config,
                body,
                is_trigger,
                executable_by,
                granted_to_auth_admin,
            ) in cur.fetchall()
        )

        cur.execute(_AUTH_USER_TRIGGERS)
        auth_user_triggers = tuple(AuthUserTrigger(*row) for row in cur.fetchall())

    return Catalog(
        server_version=server_version,
        api_roles=api_roles,
        tables=tables,
        support_tables=support_tables,
        policies=policies,
        functions=functions,
        auth_user_triggers=auth_user_triggers,
    )


def _load_tables(cur: psycopg.Cursor, params: dict) -> tuple[Table, ...]:
    """Tables of `params["schemas"]`, with their privileges, columns, keys and triggers."""
    privileges: dict[tuple[str, str], dict[str, set[str]]] = {}
    cur.execute(_TABLE_PRIVILEGES, params)
    for schema, name, role, privilege in cur.fetchall():
        privileges.setdefault((schema, name), {}).setdefault(role, set()).add(privilege)

    details: dict[tuple[str, str], list[Column]] = {}
    cur.execute(_COLUMNS, params)
    for schema, name, *column in cur.fetchall():
        column_name, type_, base, category, length, not_null, default, identity, gen, labels = (
            column
        )
        details.setdefault((schema, name), []).append(
            Column(
                name=column_name,
                type=type_,
                base_type=base,
                category=category,
                max_length=length,
                not_null=not_null,
                has_default=default,
                identity=identity,
                generated=gen,
                enum_labels=tuple(labels),
            )
        )

    primary_keys: dict[tuple[str, str], tuple[str, ...]] = {}
    foreign_keys: dict[tuple[str, str], list[ForeignKey]] = {}
    cur.execute(_KEYS, params)
    for (
        schema,
        name,
        constraint,
        kind,
        columns,
        ref_schema,
        ref_table,
        ref_columns,
    ) in cur.fetchall():
        if kind == "p":
            primary_keys[(schema, name)] = tuple(columns)
        else:
            foreign_keys.setdefault((schema, name), []).append(
                ForeignKey(constraint, tuple(columns), ref_schema, ref_table, tuple(ref_columns))
            )

    triggers: dict[tuple[str, str], list[TableTrigger]] = {}
    cur.execute(_TABLE_TRIGGERS, params)
    for schema, name, trigger, function_schema, function_name in cur.fetchall():
        triggers.setdefault((schema, name), []).append(
            TableTrigger(trigger, function_schema, function_name)
        )

    cur.execute(_TABLES, params)
    return tuple(
        Table(
            schema=schema,
            name=name,
            rls_enabled=rls_enabled,
            columns=tuple(columns),
            privileges={
                role: frozenset(privs) for role, privs in privileges.get((schema, name), {}).items()
            },
            column_details=tuple(details.get((schema, name), ())),
            primary_key=primary_keys.get((schema, name), ()),
            foreign_keys=tuple(foreign_keys.get((schema, name), ())),
            triggers=tuple(triggers.get((schema, name), ())),
        )
        for schema, name, rls_enabled, columns in cur.fetchall()
    )

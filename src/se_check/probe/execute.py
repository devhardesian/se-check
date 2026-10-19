"""Run a probe plan: the only part of the probe that touches the database.

Everything happens in one transaction that is always rolled back. Synthetic users and rows are
inserted first; then each step runs as its persona inside a savepoint that is rolled back as
well, even when the step succeeds, so steps don't see each other's effects. Rolling back the
savepoint also undoes `SET LOCAL ROLE` and the JWT claims.

Only rows the probe created are ever addressed, by the keys it generated, and nothing but
outcomes and SQLSTATEs leaves this module: error messages can carry values. A synthetic row
may point at an existing row of reference data (`ExistingRow`): the database copies its key
into a transaction-local setting, and se-check only learns whether there was one.
"""

from __future__ import annotations

import contextlib
import json
import uuid
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any

import psycopg
from psycopg import sql
from psycopg.types.json import Jsonb

from se_check.probe.claims import describe_paths
from se_check.probe.model import (
    PERSONAS_BY_NAME,
    ExistingRow,
    Null,
    Observation,
    Outcome,
    Persona,
    ProbePlan,
    RowRecipe,
    RowValue,
    Skip,
    StandIn,
    Step,
    Text,
    UserId,
    Value,
)

STATEMENT_TIMEOUT = "5s"
LOCK_TIMEOUT = "1s"
"""Give up quickly instead of queueing behind the application's locks."""

INSUFFICIENT_PRIVILEGE = "42501"


# What to do when a synthetic row can't be inserted, by SQLSTATE ("22": any data exception).
_INSERT_HINTS = {
    "23514": 'set values it accepts in [probe.values."{table}"]',
    "23502": 'set a value in [probe.values."{table}"]',
    "23505": "a row with that key exists already, as in a single-row settings table: list it "
    "in [probe] skip_tables",
    "22": 'set a value of the right form in [probe.values."{table}"]',
    "P0001": 'a trigger refused it: set values it accepts in [probe.values."{table}"], or list '
    "it in [probe] skip_tables",
    "55P03": "another transaction holds a lock on it",
}


class _Unresolved(Exception):
    """A value depends on a row that could not be created or found."""

    def __init__(self, table: str, reason: str | None = None) -> None:
        super().__init__(table)
        self.table = table
        self.reason = reason or f"needs a row of {table}, which could not be created"


@dataclass
class _Values:
    """A synthetic row as SQL: an expression per column, and what se-check knows of it."""

    columns: list[str] = field(default_factory=list)
    exprs: list[sql.Composable] = field(default_factory=list)
    params: list[Any] = field(default_factory=list)
    known: dict[str, Any] = field(default_factory=dict)
    """Columns whose value se-check passed itself."""
    unseen: set[str] = field(default_factory=set)
    """Columns an existing row supplied: never read back."""
    stand_ins: list[StandIn] = field(default_factory=list)


@dataclass
class Execution:
    observations: list[Observation] = field(default_factory=list)
    skipped: list[Skip] = field(default_factory=list)
    stand_ins: list[StandIn] = field(default_factory=list)
    """References that could not point at the row they were meant to, and what they took."""
    personas: list[str] = field(default_factory=list)
    """How each persona was set up, in words."""
    statements: int = 0
    blocked: str | None = None
    """Why nothing could run, e.g. the session user cannot become the API roles."""
    claims: list[str] = field(default_factory=list)
    """Where the personas' JWT claims came from."""


def execute(conn: psycopg.Connection, plan: ProbePlan) -> Execution:
    run = _Run(conn, plan)
    with conn.transaction(force_rollback=True), conn.cursor() as cur:
        run.cur = cur
        cur.execute(f"set local statement_timeout = '{STATEMENT_TIMEOUT}'")
        cur.execute(f"set local lock_timeout = '{LOCK_TIMEOUT}'")
        run.result.blocked = run.check_roles()
        if run.result.blocked:
            return run.result
        run.create_users()
        run.create_rows()
        run.add_memberships()
        run.prepare_claims()
        run.describe_personas()
        for step in plan.steps:
            run.run_step(step)
    return run.result


class _Run:
    def __init__(self, conn: psycopg.Connection, plan: ProbePlan) -> None:
        self.conn = conn
        self.plan = plan
        self.cur: psycopg.Cursor
        self.result = Execution()
        self.rows: dict[str, dict[str, Any]] = {}
        self.users_created = False
        self.user_columns: set[str] = set()
        self.membership_added = False
        self.hook_used = False
        self.failed_tables: set[str] = set()
        self.claims: dict[str, dict[str, Any]] = {}
        self.existing: dict[tuple[str, tuple[str, ...]], dict[str, str] | str] = {}
        """(table, columns) -> the settings holding an existing row's key, or why there is none."""
        self.seeding = False

    # --- setup --------------------------------------------------------------------------------

    def check_roles(self) -> str | None:
        """Every step starts with SET ROLE: if that fails, all of them would look denied."""
        for role in dict.fromkeys(p.role for p in PERSONAS_BY_NAME.values()):
            try:
                with self.conn.transaction(force_rollback=True):
                    self.cur.execute(sql.SQL("set local role {}").format(sql.Identifier(role)))
            except psycopg.Error as exc:
                return (
                    f"the session user cannot SET ROLE {role} ({exc.sqlstate}): grant it the "
                    "API roles, as Supabase grants them to postgres"
                )
        return None

    def create_users(self) -> None:
        """One auth.users row per logged-in persona, as at signup: signup triggers run."""
        try:
            with self.conn.transaction():
                self.cur.execute(
                    "select array(select a.attname::text from pg_catalog.pg_attribute a"
                    " where a.attrelid = pg_catalog.to_regclass('auth.users')"
                    " and a.attnum > 0 and not a.attisdropped)"
                )
                columns = self.user_columns = set(self.cur.fetchone()[0])
                if "id" not in columns:
                    return  # not Supabase: personas exist only through their claims
                for persona, user_id in self.plan.users.items():
                    values = {"id": uuid.UUID(user_id)}
                    if "email" in columns:
                        values["email"] = _email(persona, user_id)
                    for column in ("aud", "role"):
                        if column in columns:
                            values[column] = "authenticated"
                    self._execute(_insert(("auth", "users"), list(values)), list(values.values()))
            self.users_created = True
        except psycopg.Error as exc:
            self.result.skipped.append(
                Skip("auth.users", f"could not create the synthetic users ({exc.sqlstate})")
            )

    def create_rows(self) -> None:
        seed_role = self._seed_role()
        if seed_role:
            self.cur.execute(sql.SQL("set local role {}").format(sql.Identifier(seed_role)))
        self.seeding = True
        try:
            for recipe in self.plan.fixtures:
                self._create_row(recipe)
            # Inserts of the steps may need existing rows too: look for them now, as the role
            # that seeds, not as a persona whom RLS may hide them from.
            for step in self.plan.steps:
                if step.recipe is not None and step.table_name not in self.failed_tables:
                    with contextlib.suppress(_Unresolved):
                        self._values(step.recipe)
        finally:
            self.seeding = False
            if seed_role:
                self.cur.execute("reset role")

    def _seed_role(self) -> str | None:
        """None to seed as the session user: it bypasses RLS (Supabase's `postgres` does)."""
        self.cur.execute(
            "select rolsuper or rolbypassrls from pg_catalog.pg_roles where rolname = session_user"
        )
        if self.cur.fetchone()[0]:
            return None
        self.cur.execute(
            "select r.rolbypassrls and pg_catalog.pg_has_role(session_user, r.oid, 'MEMBER')"
            " from pg_catalog.pg_roles r where r.rolname = 'service_role'"
        )
        row = self.cur.fetchone()
        return "service_role" if row and row[0] else None

    def _create_row(self, recipe: RowRecipe) -> None:
        if recipe.table_name in self.failed_tables:
            return
        try:
            row = self._values(recipe)
        except _Unresolved as exc:
            self._fail(recipe.table_name, exc.reason, exc.table)
            return
        returning = tuple(column for column in recipe.returning if column not in row.unseen)
        try:
            with self.conn.transaction():
                self._execute(_recipe_statement(recipe, row, returning), row.params)
                returned = self.cur.fetchone() if returning else ()
        except psycopg.Error as exc:
            self._fail(recipe.table_name, _insert_failure(recipe.table_name, exc))
            return
        if returning and returned is None:
            self._fail(recipe.table_name, "a trigger dropped the synthetic row")
            return
        self.rows[recipe.key] = {**row.known, **dict(zip(returning, returned or (), strict=True))}
        for stand_in in row.stand_ins:
            if stand_in not in self.result.stand_ins:
                self.result.stand_ins.append(stand_in)

    def _values(self, recipe: RowRecipe) -> _Values:
        """The row's values as SQL. A reference whose row is missing takes its fallback."""
        row = _Values()
        taken: dict[tuple[str, bool], list[str]] = {}
        for column, value in recipe.values:
            if isinstance(value, RowValue) and value.fallback and not self._has(value):
                if isinstance(value.fallback, Null):
                    taken.setdefault((_table_of(value.row), False), []).append(column)
                value = value.fallback
            if isinstance(value, ExistingRow):
                taken.setdefault((value.table_name, True), []).append(column)
            row.columns.append(column)
            if isinstance(value, ExistingRow):
                setting = self._existing(value)
                row.unseen.add(column)
                row.exprs.append(
                    sql.SQL("pg_catalog.current_setting({})::{}").format(
                        sql.Literal(setting), sql.SQL(value.cast)
                    )
                )
                continue
            param = self._resolve(value)
            row.exprs.append(sql.Placeholder())
            row.params.append(param)
            row.known[column] = param
        row.stand_ins = [
            StandIn(recipe.table_name, tuple(columns), parent, existing)
            for (parent, existing), columns in taken.items()
        ]
        return row

    def _existing(self, ref: ExistingRow) -> str:
        """The setting that holds `ref.column` of an existing row of `ref`'s table. Only while
        seeding: as a persona, RLS could hide the rows, and the step's savepoint would undo it."""
        key = (ref.table_name, ref.ref_columns)
        if key not in self.existing:
            if not self.seeding:
                raise _Unresolved(ref.table_name)
            self.existing[key] = self._find_existing(ref)
        found = self.existing[key]
        if isinstance(found, str):
            raise _Unresolved(ref.table_name, f"needs a row of {ref.table_name}, {found}")
        return found[ref.column]

    def _find_existing(self, ref: ExistingRow) -> dict[str, str] | str:
        """Copy the key of one existing row into transaction-local settings, inside the
        database: only whether there was a row comes back."""
        settings = {
            column: f"se_check.ref_{len(self.existing)}_{i}"
            for i, column in enumerate(ref.ref_columns)
        }
        columns = [sql.Identifier(column) for column in ref.ref_columns]
        statement = sql.SQL(
            "select bool_and(found) from (select {} as found from"
            " (select {} from {} where {} order by {} limit 1) s) q"
        ).format(
            sql.SQL(" and ").join(
                sql.SQL("pg_catalog.set_config({}, s.{}::text, true) is not null").format(
                    sql.Literal(settings[column]), sql.Identifier(column)
                )
                for column in ref.ref_columns
            ),
            sql.SQL(", ").join(columns),
            sql.Identifier(ref.schema, ref.table),
            sql.SQL(" and ").join(sql.SQL("{} is not null").format(c) for c in columns),
            sql.SQL(", ").join(columns),
        )
        try:
            with self.conn.transaction():
                self._execute(statement, None)
                found = self.cur.fetchone()[0]
        except psycopg.Error as exc:
            return (
                "which has no synthetic row, and se-check could not look for an existing one "
                f"({exc.sqlstate})"
            )
        if not found:
            return "which has no synthetic row, and no existing row se-check could use"
        return settings

    def _fail(self, table: str, reason: str, cause: str | None = None) -> None:
        if table not in self.failed_tables:
            self.failed_tables.add(table)
            self.result.skipped.append(Skip(table, reason, cause))

    def add_memberships(self) -> None:
        """Run `[probe] membership` for the personas that belong to a tenant."""
        if not self.plan.membership:
            return
        try:
            with self.conn.transaction():
                for persona in PERSONAS_BY_NAME.values():
                    if persona.tenant is None or persona.name not in self.plan.users:
                        continue
                    self._execute(
                        self.plan.membership,
                        {
                            "user": uuid.UUID(self.plan.users[persona.name]),
                            "tenant": self._tenant_id(persona.tenant),
                        },
                    )
            self.membership_added = True
        except (psycopg.Error, _Unresolved) as exc:
            state = exc.sqlstate if isinstance(exc, psycopg.Error) else "no tenant row"
            self.result.skipped.append(
                Skip("[probe] membership", f"the membership SQL failed ({state})")
            )

    def prepare_claims(self) -> None:
        """Every persona's JWT claims, as Supabase Auth would issue them: the standard ones, the
        tenant claims the policies read, `[probe] claims`; stored in auth.users too, since the
        JWT mirrors it; then passed through the custom access token hook."""
        for persona in PERSONAS_BY_NAME.values():
            self.claims[persona.name] = self._claims(persona)
        self._store_metadata()
        if self.plan.access_token_hook:
            self._run_hook(*self.plan.access_token_hook)
        # The configuration has the last word, over the hook too.
        for persona in PERSONAS_BY_NAME.values():
            if persona.logged_in:
                extra = _substitute(
                    self.plan.claims,
                    self.plan.users[persona.name],
                    self._tenant_text(persona.tenant),
                )
                self.claims[persona.name] = _merge(self.claims[persona.name], extra)

        sources = [
            f"{path} (read by your policies)" for path in describe_paths(self.plan.inferred_claims)
        ]
        sources += [f"{path} (from [probe] claims)" for path in describe_paths(self.plan.claims)]
        if self.hook_used:
            schema, name = self.plan.access_token_hook
            sources.append(f"whatever {schema}.{name}() adds (the access token hook)")
        self.result.claims = sources

    def _claims(self, persona: Persona) -> dict[str, Any]:
        """What PostgREST would put in `request.jwt.claims` for this caller, before the hook."""
        if not persona.logged_in:
            return {"iss": "supabase", "role": persona.role}
        user_id = self.plan.users[persona.name]
        claims: dict[str, Any] = {
            "iss": "supabase",
            "sub": user_id,
            "role": persona.role,
            "aud": "authenticated",
            "email": _email(persona.name, user_id),
            "app_metadata": {"provider": "email", "providers": ["email"]},
            "user_metadata": {},
            "is_anonymous": False,
        }
        template = _merge(dict(self.plan.inferred_claims), self.plan.claims)
        claims = _merge(claims, _substitute(template, user_id, self._tenant_text(persona.tenant)))
        if persona.forged_tenant and "user_metadata" in template:
            forged = self._tenant_text(persona.forged_tenant)
            metadata = _substitute(template["user_metadata"], user_id, forged)
            claims["user_metadata"] = _merge(claims["user_metadata"], metadata)
        return claims

    def _store_metadata(self) -> None:
        """auth.users holds what the JWT's app_metadata and user_metadata carry."""
        columns = {"raw_app_meta_data": "app_metadata", "raw_user_meta_data": "user_metadata"}
        columns = {c: key for c, key in columns.items() if c in self.user_columns}
        if not self.users_created or not columns:
            return
        try:
            with self.conn.transaction():
                for name, user_id in self.plan.users.items():
                    claims = self.claims[name]
                    statement = sql.SQL("update auth.users set {} where id = %s").format(
                        sql.SQL(", ").join(
                            sql.SQL("{} = %s").format(sql.Identifier(c)) for c in columns
                        )
                    )
                    params = [Jsonb(claims.get(key, {})) for key in columns.values()]
                    self._execute(statement, [*params, uuid.UUID(user_id)])
        except psycopg.Error as exc:
            self.result.skipped.append(
                Skip("auth.users", f"could not store the personas' metadata ({exc.sqlstate})")
            )

    def _run_hook(self, schema: str, name: str) -> None:
        """Call the custom access token hook as Supabase Auth does at sign-in."""
        function = sql.Identifier(schema, name)
        new_claims: dict[str, dict[str, Any]] = {}
        try:
            with self.conn.transaction():
                for persona, user_id in self.plan.users.items():
                    event = {
                        "user_id": user_id,
                        "claims": self.claims[persona],
                        "authentication_method": "password",
                    }
                    self._execute(sql.SQL("select {}(%s)").format(function), [Jsonb(event)])
                    result = self.cur.fetchone()[0]
                    if isinstance(result, dict) and isinstance(result.get("claims"), dict):
                        new_claims[persona] = result["claims"]
        except psycopg.Error as exc:
            self.result.skipped.append(
                Skip(f"{schema}.{name}()", f"the access token hook failed ({exc.sqlstate})")
            )
            return
        self.claims.update(new_claims)
        self.hook_used = bool(new_claims)

    def describe_personas(self) -> None:
        for persona in PERSONAS_BY_NAME.values():
            how = persona.describe()
            if persona.logged_in:
                how += ", synthetic user in auth.users" if self.users_created else ", claims only"
            if self.membership_added and persona.tenant:
                how += ", membership from [probe] membership"
            self.result.personas.append(how)

    # --- steps --------------------------------------------------------------------------------

    def run_step(self, step: Step) -> None:
        if step.table_name in self.failed_tables:
            return
        try:
            statement, params = self._statement(step)
        except _Unresolved:
            return
        claims = self.claims[step.persona]
        persona = PERSONAS_BY_NAME[step.persona]
        try:
            with self.conn.transaction(force_rollback=True):
                self.cur.execute(sql.SQL("set local role {}").format(sql.Identifier(persona.role)))
                self.cur.execute(
                    "select pg_catalog.set_config('request.jwt.claims', %s, true)",
                    (json.dumps(claims),),
                )
                self._execute(statement, params)
                if step.command == "SELECT":
                    reached = bool(self.cur.fetchone()[0])
                else:
                    reached = self.cur.rowcount > 0
            outcome = Outcome.ALLOWED if reached else Outcome.FILTERED
            self.result.observations.append(Observation(step, outcome))
        except psycopg.Error as exc:
            outcome = (
                Outcome.DENIED if exc.sqlstate == INSUFFICIENT_PRIVILEGE else Outcome.INCONCLUSIVE
            )
            self.result.observations.append(Observation(step, outcome, exc.sqlstate))

    def _statement(self, step: Step) -> tuple[sql.Composable, list[Any]]:
        """The statement as PostgREST would send it: filtered on the primary key."""
        table = sql.Identifier(step.schema, step.table)
        if step.command == "INSERT":
            assert step.recipe is not None
            row = self._values(step.recipe)
            return _recipe_statement(step.recipe, row, step.recipe.returning), row.params
        assert step.target is not None
        if step.target not in self.rows:
            raise _Unresolved(step.target)
        row = self.rows[step.target]
        where = sql.SQL(" and ").join(
            sql.SQL("{} = %s").format(sql.Identifier(column)) for column in step.key
        )
        params = [row[column] for column in step.key]
        if step.command == "SELECT":
            statement = sql.SQL("select exists(select 1 from {} where {})").format(table, where)
        elif step.command == "UPDATE":
            column = sql.Identifier(step.set_column)
            if step.value is None:
                statement = sql.SQL("update {} set {} = {} where {}").format(
                    table, column, column, where
                )
            else:
                statement = sql.SQL("update {} set {} = %s where {}").format(table, column, where)
                params = [self._resolve(step.value), *params]
        else:
            statement = sql.SQL("delete from {} where {}").format(table, where)
        return statement, params

    # --- helpers ------------------------------------------------------------------------------

    def _tenant_id(self, tenant: str) -> Any:
        return self._resolve(self.plan.tenant_ids[tenant])

    def _tenant_text(self, tenant: str | None) -> str | None:
        """A tenant's id as a claim carries it; None without one (or without its row)."""
        if tenant is None or tenant not in self.plan.tenant_ids:
            return None
        try:
            return str(self._tenant_id(tenant))
        except _Unresolved:
            return None

    def _has(self, value: RowValue) -> bool:
        return value.column in self.rows.get(value.row, {})

    def _resolve(self, value: Value) -> Any:
        """A value se-check passes as a parameter (not an existing row's: see `_values`)."""
        if isinstance(value, Text):
            return value.text
        if isinstance(value, UserId):
            return uuid.UUID(self.plan.users[value.persona])
        if isinstance(value, Null):
            return None
        assert isinstance(value, RowValue)
        row = self.rows.get(value.row)
        if row is None or value.column not in row:
            raise _Unresolved(_table_of(value.row))
        return row[value.column]

    def _execute(self, statement: sql.Composable | str, params: Any) -> None:
        self.result.statements += 1
        self.cur.execute(statement, params)


def _insert(
    table: tuple[str, str], columns: list[str], exprs: list[sql.Composable] | None = None
) -> sql.Composed:
    return sql.SQL("insert into {} ({}) values ({})").format(
        sql.Identifier(*table),
        sql.SQL(", ").join(map(sql.Identifier, columns)),
        sql.SQL(", ").join(exprs if exprs is not None else sql.Placeholder() * len(columns)),
    )


def _recipe_statement(recipe: RowRecipe, row: _Values, returning: tuple[str, ...]) -> sql.Composed:
    columns = row.columns
    table = (recipe.schema, recipe.table)
    if columns:
        statement = _insert(table, columns, row.exprs)
    else:
        statement = sql.SQL("insert into {} default values").format(sql.Identifier(*table))
    if recipe.conflict:
        updated = [c for c in columns if c not in recipe.conflict] or [recipe.conflict[0]]
        statement += sql.SQL(" on conflict ({}) do update set {}").format(
            sql.SQL(", ").join(map(sql.Identifier, recipe.conflict)),
            sql.SQL(", ").join(
                sql.SQL("{0} = excluded.{0}").format(sql.Identifier(c)) for c in updated
            ),
        )
    if returning:
        statement += sql.SQL(" returning {}").format(
            sql.SQL(", ").join(map(sql.Identifier, returning))
        )
    return statement


def _insert_failure(table: str, exc: psycopg.Error) -> str:
    """Why a synthetic row could not be inserted: SQLSTATE and names, never the message."""
    state = exc.sqlstate or "?"
    detail = [state]
    if exc.diag.constraint_name:
        detail.append(f"constraint {exc.diag.constraint_name}")
    if exc.diag.column_name:
        detail.append(f"column {exc.diag.column_name}")
    reason = f"could not insert a synthetic row ({', '.join(detail)})"
    hint = _INSERT_HINTS.get(state) or _INSERT_HINTS.get(state[:2])
    return f"{reason}: {hint.format(table=table)}" if hint else reason


def _table_of(row_key: str) -> str:
    """`public.tenants` from a synthetic row's key (`public.tenants@A`, `...#alice`)."""
    return row_key.split("@")[0].split("#")[0]


def _email(persona: str, user_id: str) -> str:
    return f"{persona}-{user_id[:8]}@se-check.invalid"


def _substitute(value: Any, user: str, tenant: str | None) -> Any:
    """Replace the strings "{user}" and "{tenant}"; drop what needs a tenant the persona lacks."""
    if isinstance(value, Mapping):
        out = {}
        for key, item in value.items():
            replaced = _substitute(item, user, tenant)
            if replaced is not _DROP:
                out[key] = replaced
        return out
    if isinstance(value, list):
        return [r for r in (_substitute(item, user, tenant) for item in value) if r is not _DROP]
    if value == "{user}":
        return user
    if value == "{tenant}":
        return tenant if tenant is not None else _DROP
    return value


_DROP = object()


def _merge(base: dict[str, Any], extra: Mapping[str, Any]) -> dict[str, Any]:
    merged = dict(base)
    for key, value in extra.items():
        if isinstance(value, Mapping) and isinstance(merged.get(key), dict):
            merged[key] = _merge(merged[key], value)
        else:
            merged[key] = value
    return merged

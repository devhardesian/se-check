"""Synthetic rows: a value for every column a row needs, worked out without the database."""

from __future__ import annotations

import random
import re
import uuid
from collections.abc import Mapping
from dataclasses import dataclass

from se_check.catalog import Column, ForeignKey, Table
from se_check.config import AuditConfig, ProbeConfig
from se_check.probe.model import (
    NULL,
    ExistingRow,
    Null,
    RowRecipe,
    RowValue,
    Tenancy,
    Text,
    UserId,
    Value,
)
from se_check.probe.tenancy import AUTH_USERS, tenant_column


class RecipeError(Exception):
    """No synthetic row can be made for the table; the message says why."""

    def __init__(self, reason: str, cause: str | None = None) -> None:
        super().__init__(reason)
        self.cause = cause
        """The table whose missing row it needed."""


@dataclass(frozen=True)
class RecipeContext:
    tenancy: Tenancy
    config: AuditConfig
    probe: ProbeConfig
    tenant_ids: Mapping[str, Value]
    referenced: Mapping[str, frozenset[str]]
    """Table -> its columns that foreign keys of other tables point at."""
    known: frozenset[str] = frozenset()
    """Tables in the catalog, exposed or not: the probe can fill them."""


def fixture_key(table_name: str, tenant: str | None) -> str:
    return f"{table_name}@{tenant}" if tenant else table_name


def new_uuid(rng: random.Random) -> uuid.UUID:
    return uuid.UUID(int=rng.getrandbits(128), version=4)


def build_recipe(
    table: Table,
    *,
    key: str,
    tenant: str | None,
    owner: str,
    rows: Mapping[tuple[str, str | None], str],
    ctx: RecipeContext,
    rng: random.Random,
    fixture: bool,
) -> RowRecipe:
    """A row of `table` belonging to `tenant` and to the persona `owner`.

    Foreign keys point at the synthetic rows already planned in `rows` (of the same tenant
    when there is one), user references at the owner; when that row is missing, or cannot be
    created when the probe runs, see `_stand_in`. Columns with a default are left to it,
    except the tenant column. Fixtures read back what later rows and steps need, and upsert
    rows keyed by a user, since signup triggers often create them already.
    """
    name = table.qualified_name
    values: dict[str, Value] = {
        column: Text(text) for column, text in ctx.probe.values.get(name, {}).items()
    }

    for fk in table.foreign_keys:
        if any(column in values for column in fk.columns):
            continue
        nullable = not all(_not_null(table, column) for column in fk.columns)
        if fk.ref_name == AUTH_USERS:
            if fk.ref_columns == ("id",):
                values[fk.columns[0]] = UserId(owner)
            elif not nullable:
                raise RecipeError(f"{fk.name} references {AUTH_USERS} by a column other than id")
            continue
        parent = None
        if fk.ref_name != name:
            parent = rows.get((fk.ref_name, tenant)) or rows.get((fk.ref_name, None))
        stand_in = _stand_in(table, fk, ctx)
        if parent is not None:
            for column, ref_column in zip(fk.columns, fk.ref_columns, strict=True):
                fallback = stand_in[column] if stand_in else None
                values[column] = RowValue(parent, ref_column, fallback)
        elif not nullable:
            if stand_in:
                values.update(stand_in)
                continue
            if fk.ref_name == name:
                raise RecipeError(f"{fk.name} points at the table itself and cannot be NULL")
            if fk.ref_name not in ctx.known:
                raise RecipeError(
                    f"needs a row of {fk.ref_name}, in a schema se-check leaves alone"
                )
            raise RecipeError(
                f"needs a row of {fk.ref_name}, which has no synthetic row", cause=fk.ref_name
            )

    tenant_col = tenant_column(table, ctx.config)
    for column in table.column_details:
        if column.name in values or column.generated or column.identity:
            continue
        if column.name == tenant_col and tenant is not None:
            values[column.name] = _tenant_value(column, tenant, ctx)
            continue
        if not column.not_null or column.has_default:
            continue
        text = synthetic_value(column, rng)
        if text is None:
            raise RecipeError(
                f"cannot make up a value for {column.name} ({column.type}): set one in "
                f'[probe.values."{name}"]'
            )
        values[column.name] = Text(text)

    order = {column.name: i for i, column in enumerate(table.column_details)}
    ordered = tuple(sorted(values.items(), key=lambda item: order.get(item[0], len(order))))
    returning: tuple[str, ...] = ()
    conflict: tuple[str, ...] = ()
    if fixture:
        wanted = set(table.primary_key) | ctx.referenced.get(name, frozenset())
        returning = tuple(c.name for c in table.column_details if c.name in wanted)
        if any(isinstance(values.get(column), UserId) for column in table.primary_key):
            conflict = table.primary_key
    return RowRecipe(
        key=key,
        schema=table.schema,
        table=table.name,
        tenant=tenant,
        values=ordered,
        returning=returning,
        conflict=conflict,
    )


def _stand_in(
    table: Table, fk: ForeignKey, ctx: RecipeContext
) -> dict[str, Null | ExistingRow] | None:
    """What a reference takes when the row it should point at is missing: NULL if it may be
    NULL, else a row the parent table already holds, when that table is reference data (not
    tenant- or user-scoped) se-check knows. Never for the tenant column, which says whose the
    row is, nor for the primary key, which steps address the row by: se-check would have to
    read the value."""
    if fk.ref_name == table.qualified_name or tenant_column(table, ctx.config) in fk.columns:
        return None
    if not any(_not_null(table, column) for column in fk.columns):
        return dict.fromkeys(fk.columns, NULL)
    if (
        fk.ref_name not in ctx.known
        or ctx.tenancy.scope_of(fk.ref_name)
        or set(fk.columns) & set(table.primary_key)
    ):
        return None
    return {
        column: ExistingRow(
            fk.ref_schema, fk.ref_table, fk.ref_columns, ref_column, _type(table, column)
        )
        for column, ref_column in zip(fk.columns, fk.ref_columns, strict=True)
    }


def _type(table: Table, name: str) -> str:
    column = table.column(name)
    return column.type if column is not None else "text"


def _tenant_value(column: Column, tenant: str, ctx: RecipeContext) -> Value:
    value = ctx.tenant_ids[tenant]
    if ctx.tenancy.tenant_table is None and column.base_type not in ("uuid", "text", "varchar"):
        # Made-up tenant ids are uuids: they can't go into an integer tenant column.
        raise RecipeError(
            f"tenant column {column.name} is {column.type} and there is no tenant table to take "
            "ids from"
        )
    return value


def _not_null(table: Table, name: str) -> bool:
    column = table.column(name)
    return column is not None and column.not_null


_TOP_LABEL = re.compile(r"admin|owner|super|staff|manager", re.IGNORECASE)


def escalation_values(column: Column) -> list[str]:
    """Values that would raise a user's privileges through this column, as text."""
    if column.enum_labels:
        top = [label for label in column.enum_labels if _TOP_LABEL.search(label)]
        return (top or [column.enum_labels[-1]])[:2]
    category, base = column.category, column.base_type
    if category == "B":
        return ["true"]
    if category == "S":
        if column.name.lower() in ("plan", "tier"):
            return ["enterprise", "pro"]
        return ["admin", "owner"]
    if category == "A":
        return ["{admin}"]
    if category == "N":
        return ["32767" if base == "int2" else "2147483647" if base in ("int4", "int8") else "999"]
    return []


def synthetic_value(column: Column, rng: random.Random) -> str | None:
    """A value of the column's type, as text; None when se-check can't make one up."""
    if column.enum_labels:
        return column.enum_labels[0]
    category, base = column.category, column.base_type
    if category == "A":
        return "{}"
    if category == "B":
        return "false"
    if category == "D":
        return "now"
    if category == "T":
        return "0"
    if category == "N":
        if base == "int2":
            return str(rng.randint(1, 32767))
        if base in ("int4", "int8"):
            return str(rng.randint(1, 2**31 - 1))
        return "1"
    if category == "S":
        text = f"se-check-{rng.getrandbits(48):012x}"
        return text[-column.max_length :] if column.max_length else text
    if category == "I":
        return "192.0.2.1"  # TEST-NET-1, reserved for documentation
    if base == "uuid":
        return str(new_uuid(rng))
    if base in ("json", "jsonb"):
        return "{}"
    if base == "bytea":
        return ""
    return None

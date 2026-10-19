"""Data types of the dynamic probe: personas, synthetic rows, steps and what came of them."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

TENANT_A = "A"
TENANT_B = "B"
"""Sides of the probe. On tenant-scoped tables they are tenants; on tables whose rows belong to
a user they stand for alice's rows (A) and bob's (B)."""


@dataclass(frozen=True)
class Persona:
    name: str
    role: str
    """The database role PostgREST would switch to for this caller."""
    tenant: str | None = None
    logged_in: bool = True
    forged_tenant: str | None = None
    """A tenant this persona wrote into her own user_metadata, as any user can."""

    def describe(self) -> str:
        if not self.logged_in:
            return f"{self.name} (the anon key)"
        if self.forged_tenant:
            return f"{self.name} (wrote tenant {self.forged_tenant} into her own user_metadata)"
        if self.tenant is None:
            return f"{self.name} (logged in, member of no tenant)"
        return f"{self.name} (member of tenant {self.tenant})"


ANON = Persona("anon", "anon", logged_in=False)
ALICE = Persona("alice", "authenticated", TENANT_A)
BOB = Persona("bob", "authenticated", TENANT_B)
OUTSIDER = Persona("outsider", "authenticated")
MALLORY = Persona("mallory", "authenticated", forged_tenant=TENANT_B)
PERSONAS = (ANON, ALICE, BOB, OUTSIDER, MALLORY)
PERSONAS_BY_NAME = {persona.name: persona for persona in PERSONAS}

OWNERS = {TENANT_A: ALICE.name, TENANT_B: BOB.name, None: BOB.name}
"""Whose the synthetic rows of each side are: bob owns the target rows."""

# What a step tries; each maps to a rule (probe/rules.py).
ANON_ACCESS = "anon"
CROSS_TENANT = "cross-tenant"
CROSS_USER = "cross-user"
TENANT_HOP = "tenant-hop"
"""Move a row of tenant A into tenant B."""
SELF_ESCALATION = "self-escalation"
"""Change a privilege column, or the tenant, of your own row."""


# --- values of synthetic rows -----------------------------------------------------------------


@dataclass(frozen=True)
class Text:
    """A value written as text, which Postgres casts to the column's type."""

    text: str


@dataclass(frozen=True)
class UserId:
    """The id of a persona's synthetic user."""

    persona: str


@dataclass(frozen=True)
class Null:
    """SQL NULL."""


NULL = Null()


@dataclass(frozen=True)
class ExistingRow:
    """A column of a row the table already holds, for references to reference data (plans,
    statuses) when it has no synthetic row. The database picks the row and copies its key into
    a transaction-local setting: se-check never sees the value."""

    schema: str
    table: str
    ref_columns: tuple[str, ...]
    """The columns the reference points at: one row supplies all of them."""
    column: str
    cast: str
    """The type of the column that takes the value, as Postgres prints it."""

    @property
    def table_name(self) -> str:
        return f"{self.schema}.{self.table}"


@dataclass(frozen=True)
class RowValue:
    """A column of a synthetic row inserted earlier, read back with RETURNING."""

    row: str
    column: str
    fallback: Null | ExistingRow | None = None
    """What to use instead when that row could not be created."""


Value = Text | UserId | RowValue | ExistingRow | Null


@dataclass(frozen=True)
class RowRecipe:
    """How to insert one synthetic row; worked out without the database."""

    key: str
    schema: str
    table: str
    tenant: str | None
    values: tuple[tuple[str, Value], ...] = ()
    returning: tuple[str, ...] = ()
    """Columns to read back: the primary key, and what other rows reference."""
    conflict: tuple[str, ...] = ()
    """Upsert on these columns: the row may exist already (one row per user, made at signup)."""

    @property
    def table_name(self) -> str:
        return f"{self.schema}.{self.table}"

    def depends_on(self) -> set[str]:
        return {value.row for _, value in self.values if isinstance(value, RowValue)}


# --- what the probe does ----------------------------------------------------------------------


@dataclass(frozen=True)
class Step:
    """One statement run as a persona, in a savepoint that is always rolled back."""

    persona: str
    schema: str
    table: str
    command: str
    """SELECT, INSERT, UPDATE or DELETE."""
    tenant: str | None
    """Side of the row it targets or inserts (None for tables without tenants or owners)."""
    scenario: str = CROSS_TENANT
    target: str | None = None
    """Key of the synthetic row it reads, updates or deletes."""
    key: tuple[str, ...] = ()
    """Primary key columns that address the target, as a PostgREST filter would."""
    set_column: str | None = None
    """UPDATE sets this column: to `value`, or to its own value."""
    value: Value | None = None
    value_label: str | None = None
    """How `value` reads in a finding: `'admin'`, `<tenant B>`."""
    recipe: RowRecipe | None = None
    """INSERT inserts this row."""
    target_label: str = "synthetic row"
    """The row in words, for the statement shown in findings: `row of tenant B`."""

    @property
    def table_name(self) -> str:
        return f"{self.schema}.{self.table}"


class Outcome(Enum):
    ALLOWED = "allowed"
    """The statement reached the target row, or inserted its row."""
    FILTERED = "filtered"
    """It ran, but touched no row: RLS hid the target."""
    DENIED = "denied"
    """42501: a policy's WITH CHECK, or a missing privilege."""
    INCONCLUSIVE = "inconclusive"
    """Any other error (constraint, trigger exception, timeout): says nothing about access."""


@dataclass(frozen=True)
class Observation:
    step: Step
    outcome: Outcome
    sqlstate: str | None = None


@dataclass(frozen=True)
class Skip:
    table: str
    reason: str
    cause: str | None = None
    """The table whose missing row this one needed: the report groups skips by it."""


@dataclass(frozen=True)
class StandIn:
    """A reference a synthetic row could not point at the row it was meant to."""

    table: str
    columns: tuple[str, ...]
    parent: str
    existing: bool
    """True: a row the parent table already holds; False: NULL."""

    def describe(self) -> str:
        columns = ", ".join(self.columns)
        if self.existing:
            return f"{self.table}.{columns} took an existing row of it instead"
        return f"{self.table}.{columns} was left NULL instead"


@dataclass(frozen=True)
class Tenancy:
    """How rows belong to tenants, as far as the catalog shows."""

    tenant_table: str | None = None
    tenant_key: str | None = None
    """The tenant table's column that tenant columns reference (usually `id`)."""
    scoped: Mapping[str, str] = field(default_factory=dict)
    """Tenant-scoped table -> what ties it to a tenant (a column, or a foreign key)."""
    user_scoped: Mapping[str, str] = field(default_factory=dict)
    """Table whose rows belong to a user, and no tenant -> the column naming the user."""

    def describe(self) -> str:
        parts = []
        if self.scoped:
            tables = len(self.scoped) - (1 if self.tenant_table else 0)
            head = f"tenants in {self.tenant_table}" if self.tenant_table else "no tenant table"
            parts.append(f"{head}, {_count(tables, 'tenant-scoped table')}")
        else:
            parts.append("no tenant-scoped tables found")
        if self.user_scoped:
            parts.append(_count(len(self.user_scoped), "table") + " of rows owned by a user")
        return "; ".join(parts)

    def scope_of(self, table: str) -> str | None:
        return self.scoped.get(table) or self.user_scoped.get(table)


def _count(n: int, noun: str) -> str:
    return f"{n} {noun}{'s' if n != 1 else ''}"


@dataclass(frozen=True)
class ProbePlan:
    tenancy: Tenancy
    users: Mapping[str, str]
    """Logged-in persona -> id of their synthetic user."""
    tenant_ids: Mapping[str, Value]
    """Tenant -> its id, as a value of a synthetic row or made up."""
    fixtures: tuple[RowRecipe, ...]
    """Synthetic rows, in insert order."""
    steps: tuple[Step, ...]
    skipped: tuple[Skip, ...] = ()
    claims: Mapping[str, Any] = field(default_factory=dict)
    """From `[probe] claims`: applied last."""
    inferred_claims: Mapping[str, Any] = field(default_factory=dict)
    """Tenant claims the policies read, with "{tenant}" placeholders (probe/claims.py)."""
    access_token_hook: tuple[str, str] | None = None
    """(schema, function) of the custom access token hook, called like Supabase Auth does."""
    membership: str | None = None
    blocked: str | None = None
    """Why nothing can run at all."""
    targets: tuple[str, ...] = ()
    """Exposed tables where some persona has something to try: what coverage is measured on."""
    left_out: tuple[str, ...] = ()
    """Tables that would be targets, but `[probe] skip_tables` lists them."""


@dataclass(frozen=True)
class ProbeCoverage:
    """What the probe did and did not try: "no findings" means little without it."""

    tenancy: str
    personas: tuple[str, ...]
    probed: tuple[str, ...]
    """Tables where at least one step ran to a conclusive outcome."""
    skipped: tuple[Skip, ...]
    inconclusive: tuple[Observation, ...]
    statements: int
    blocked: str | None = None
    claims: tuple[str, ...] = ()
    """Where the personas' JWT claims came from, e.g. `user_metadata.tenant_id (policies)`."""
    targets: tuple[str, ...] = ()
    """The tables the probe meant to try (ProbePlan.targets)."""
    scoped_targets: tuple[str, ...] = ()
    """The tenant-scoped ones among them, the tenant table aside."""
    left_out: tuple[str, ...] = ()
    planned_steps: int = 0
    steps_run: int = 0
    stand_ins: tuple[StandIn, ...] = ()

    @property
    def reached(self) -> tuple[str, ...]:
        probed = set(self.probed)
        return tuple(t for t in self.targets if t in probed)

    @property
    def not_reached(self) -> tuple[str, ...]:
        probed = set(self.probed)
        return tuple(t for t in self.targets if t not in probed)

    @property
    def ratio(self) -> float:
        """Share of the targets reached: 1 when there was nothing to try, 0 when blocked."""
        if self.blocked:
            return 0.0
        return len(self.reached) / len(self.targets) if self.targets else 1.0

    @property
    def complete(self) -> bool:
        return not self.blocked and not self.not_reached

    def to_dict(self) -> dict[str, Any]:
        probed = set(self.probed)
        return {
            "complete": self.complete,
            "tables": {"reached": len(self.reached), "of": len(self.targets)},
            "tenant_scoped_tables": {
                "reached": sum(1 for t in self.scoped_targets if t in probed),
                "of": len(self.scoped_targets),
            },
            "steps": {"ran": self.steps_run, "planned": self.planned_steps},
            "not_reached": list(self.not_reached),
            "left_out": list(self.left_out),
            "tenancy": self.tenancy,
            "personas": list(self.personas),
            "probed": list(self.probed),
            "skipped": [
                {"table": s.table, "reason": s.reason, "cause": s.cause} for s in self.skipped
            ],
            "stand_ins": [
                {
                    "table": s.table,
                    "columns": list(s.columns),
                    "parent": s.parent,
                    "value": "existing row" if s.existing else "null",
                }
                for s in self.stand_ins
            ],
            "inconclusive": [
                {
                    "table": o.step.table_name,
                    "command": o.step.command,
                    "persona": o.step.persona,
                    "sqlstate": o.sqlstate,
                }
                for o in self.inconclusive
            ],
            "statements": self.statements,
            "claims": list(self.claims),
            "blocked": self.blocked,
        }

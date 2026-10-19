"""Decide what the probe does: which synthetic rows to make, and which statements to try as whom.

Pure: everything here works from the catalog, so it is unit-tested without a database.
"""

from __future__ import annotations

import random
import re
from collections import defaultdict

from se_check.catalog import PRIVILEGES, Catalog, Table
from se_check.checks.base import calls, strip_sql_comments
from se_check.config import PRIVILEGED_NAMES, AuditConfig, ProbeConfig
from se_check.probe.claims import inferred_claims
from se_check.probe.fixtures import (
    RecipeContext,
    RecipeError,
    build_recipe,
    escalation_values,
    fixture_key,
    new_uuid,
)
from se_check.probe.model import (
    ALICE,
    ANON_ACCESS,
    CROSS_TENANT,
    CROSS_USER,
    OUTSIDER,
    OWNERS,
    PERSONAS,
    SELF_ESCALATION,
    TENANT_A,
    TENANT_B,
    TENANT_HOP,
    Persona,
    ProbePlan,
    RowRecipe,
    RowValue,
    Skip,
    Step,
    Tenancy,
    Text,
    Value,
)
from se_check.probe.tenancy import (
    infer_tenancy,
    is_identity_row,
    tenant_column,
    user_columns,
)

# Functions that act outside the transaction, so a rollback cannot undo them: the `http`
# extension and dblink. pg_net (`net.http_post`, Supabase webhooks) only queues requests in a
# table, which the rollback empties.
_ESCAPING_CALL = re.compile(
    r"(?:\b(\w+)\s*\.\s*)?\b(http(?:_get|_post|_put|_patch|_delete|_head)?"
    r"|dblink(?:_exec|_open|_send_query)?)\s*\(",
    re.IGNORECASE,
)

ATTACKERS = (ALICE.name, OUTSIDER.name)
"""Logged-in personas that try to reach tenant B's rows, or bob's."""


def escaping_functions(catalog: Catalog) -> set[str]:
    """Names of the functions that act outside the transaction, directly or through others."""
    bodies = [(fn.name, strip_sql_comments(fn.body)) for fn in catalog.functions if fn.body]
    escaping = {name for name, body in bodies if _calls_outside(body)}
    while True:
        found = {
            name
            for name, body in bodies
            if name not in escaping and any(calls(helper, body) for helper in escaping)
        }
        if not found:
            return escaping
        escaping |= found


def _calls_outside(body: str) -> bool:
    return any(
        match.group(1) is None or match.group(1).lower() != "net"
        for match in _ESCAPING_CALL.finditer(body)
    )


def plan_probe(
    catalog: Catalog,
    config: AuditConfig,
    probe: ProbeConfig | None = None,
    rng: random.Random | None = None,
) -> ProbePlan:
    probe = probe or ProbeConfig()
    rng = rng or random.Random()
    tenancy = infer_tenancy(catalog, config)
    users = {p.name: str(new_uuid(rng)) for p in PERSONAS if p.logged_in}
    escaping = escaping_functions(catalog)

    blocked = next(
        (
            f'a trigger on auth.users, "{trigger.name}", runs {trigger.function_name}(), which '
            "acts outside the transaction (http, dblink)"
            for trigger in catalog.auth_user_triggers
            if trigger.function_name in escaping
        ),
        None,
    )

    exposed = {table.qualified_name for table in catalog.tables}
    tables = {t.qualified_name: t for t in (*catalog.tables, *catalog.support_tables)}
    # Every table that gets no row is recorded, exposed or not: the tables that needed its row
    # name it as their cause. run_probe picks what the report shows.
    skipped: list[Skip] = []
    candidates: dict[str, Table] = {}
    for name in sorted(_needed(tables, exposed, tenancy)):
        table = tables[name]
        reason = _skip_reason(table, probe, escaping)
        if reason is None:
            candidates[name] = table
        else:
            skipped.append(Skip(name, reason))

    tenant_ids: dict[str, Value] = {}
    if tenancy.tenant_table and tenancy.tenant_key:
        tenant_ids = {
            tenant: RowValue(fixture_key(tenancy.tenant_table, tenant), tenancy.tenant_key)
            for tenant in (TENANT_A, TENANT_B)
        }
    elif tenancy.scoped:
        tenant_ids = {tenant: Text(str(new_uuid(rng))) for tenant in (TENANT_A, TENANT_B)}

    referenced: dict[str, set[str]] = defaultdict(set)
    for table in tables.values():
        for fk in table.foreign_keys:
            referenced[fk.ref_name].update(fk.ref_columns)
    ctx = RecipeContext(
        tenancy=tenancy,
        config=config,
        probe=probe,
        tenant_ids=tenant_ids,
        referenced={name: frozenset(columns) for name, columns in referenced.items()},
        known=frozenset(tables),
    )

    def parents(name: str) -> set[str]:
        """Tables whose synthetic rows this table's rows point at."""
        found = {fk.ref_name for fk in candidates[name].foreign_keys}
        if name in tenancy.scoped and tenancy.tenant_table:
            found.add(tenancy.tenant_table)  # tenant columns take the tenant rows' ids
        return found - {name}

    rows: dict[tuple[str, str | None], str] = {}
    fixtures: list[RowRecipe] = []
    pending = list(candidates)
    while pending:
        waiting = set(pending)
        ready = [name for name in pending if not parents(name) & waiting]
        batch = ready or pending  # a cycle: build what can be built, NULLs breaking it
        for name in batch:
            table = candidates[name]
            tenants = (TENANT_A, TENANT_B) if tenancy.scope_of(name) else (None,)
            try:
                recipes = [
                    build_recipe(
                        table,
                        key=fixture_key(name, tenant),
                        tenant=tenant,
                        owner=OWNERS[tenant],
                        rows=rows,
                        ctx=ctx,
                        rng=rng,
                        fixture=True,
                    )
                    for tenant in tenants
                ]
            except RecipeError as exc:
                skipped.append(Skip(name, str(exc), exc.cause))
                continue
            fixtures.extend(recipes)
            rows.update({(name, recipe.tenant): recipe.key for recipe in recipes})
        pending = [name for name in pending if name not in set(batch)]

    inferred = inferred_claims(catalog, config)
    # Mallory only differs from the outsider when tenants come from user_metadata.
    forgeable = "user_metadata" in inferred
    tried = [name for name in sorted(exposed) if _tries(tables[name], tenancy, forgeable)]
    targets = tuple(name for name in tried if name not in probe.skip_tables)

    steps: list[Step] = []
    for name, table in candidates.items():
        if name not in exposed:
            continue  # rows the API cannot reach: they are there for the others to point at
        if not table.primary_key:
            if name in targets:
                skipped.append(Skip(name, "no primary key to address its rows by"))
            continue
        side = TENANT_B if tenancy.scope_of(name) else None
        target = rows.get((name, side))
        if target is None:
            continue
        for persona in PERSONAS:
            scenario = _scenario(persona, name, tenancy, forgeable)
            if scenario is None:
                continue
            for command in PRIVILEGES:
                if not table.has_privilege(persona.role, command):
                    continue
                step = _step(table, persona, command, side, target, scenario, rows, ctx, rng)
                if step is not None:
                    steps.append(step)
        own = rows.get((name, TENANT_A))
        if own is not None and table.has_privilege(ALICE.role, "UPDATE"):
            steps.extend(_own_row_steps(table, own, rows, ctx))

    return ProbePlan(
        tenancy=tenancy,
        users=users,
        tenant_ids=tenant_ids,
        fixtures=tuple(fixtures),
        steps=tuple(steps),
        skipped=tuple(skipped),
        claims=probe.claims,
        inferred_claims=inferred,
        access_token_hook=_access_token_hook(catalog, config, escaping),
        membership=probe.membership,
        blocked=blocked,
        targets=targets,
        left_out=tuple(name for name in tried if name in probe.skip_tables),
    )


def _tries(table: Table, tenancy: Tenancy, forgeable: bool) -> bool:
    """Whether any persona has something to try on the table, given the privileges its role
    holds: the tables the probe's coverage is measured on."""
    name = table.qualified_name
    return any(
        table.has_privilege(persona.role, command)
        and not (command == "INSERT" and persona.logged_in and name == tenancy.tenant_table)
        for persona in PERSONAS
        if _scenario(persona, name, tenancy, forgeable) is not None
        for command in PRIVILEGES
    )


def _scenario(persona: Persona, table: str, tenancy: Tenancy, forgeable: bool) -> str | None:
    """What a persona tries on a table's target row, if anything."""
    if not persona.logged_in:
        return ANON_ACCESS
    if table in tenancy.scoped:
        if persona.name in ATTACKERS or (persona.forged_tenant and forgeable):
            return CROSS_TENANT
    elif table in tenancy.user_scoped and persona.name in ATTACKERS:
        return CROSS_USER
    return None


def _own_row_steps(
    table: Table, own: str, rows: dict[tuple[str, str | None], str], ctx: RecipeContext
) -> list[Step]:
    """Alice on her own row: raise her privileges, or move the row to tenant B."""
    name = table.qualified_name
    tenancy = ctx.tenancy
    identity = is_identity_row(table)
    base = {
        "persona": ALICE.name,
        "schema": table.schema,
        "table": table.name,
        "command": "UPDATE",
        "tenant": TENANT_A,
        "target": own,
        "key": table.primary_key,
    }
    steps = []
    own_label = "alice's own row"

    # Her own row: one with her user id in it, or her tenant's row in the tenant table.
    if user_columns(table) or name == tenancy.tenant_table:
        keys = set(table.primary_key).union(*(fk.columns for fk in table.foreign_keys))
        names = {n.lower() for n in (*PRIVILEGED_NAMES, *ctx.probe.privilege_columns)}
        for column in table.column_details:
            if column.name.lower() not in names or column.name in keys:
                continue
            if column.generated or column.identity == "a":
                continue
            for value in escalation_values(column):
                steps.append(
                    Step(
                        **base,
                        scenario=SELF_ESCALATION,
                        set_column=column.name,
                        value=Text(value),
                        value_label=f"'{value}'",
                        target_label=own_label,
                    )
                )

    # Tenant B, through the tenant column or the reference that makes the row tenant-scoped.
    if name in tenancy.scoped and name != tenancy.tenant_table:
        hop = _tenant_hop(table, rows, ctx)
        if hop is not None:
            column, value = hop
            steps.append(
                Step(
                    **base,
                    scenario=SELF_ESCALATION if identity else TENANT_HOP,
                    set_column=column,
                    value=value,
                    value_label=f"<tenant {TENANT_B}>",
                    target_label=own_label if identity else f"row of tenant {TENANT_A}",
                )
            )
    return steps


def _tenant_hop(
    table: Table, rows: dict[tuple[str, str | None], str], ctx: RecipeContext
) -> tuple[str, Value] | None:
    column = tenant_column(table, ctx.config)
    if column and ctx.tenant_ids:
        fk = next((fk for fk in table.foreign_keys if fk.columns == (column,)), None)
        if fk is None or fk.ref_name == ctx.tenancy.tenant_table:
            return column, ctx.tenant_ids[TENANT_B]
    for fk in table.foreign_keys:
        parent = rows.get((fk.ref_name, TENANT_B))
        if len(fk.columns) == 1 and fk.ref_name in ctx.tenancy.scoped and parent:
            return fk.columns[0], RowValue(parent, fk.ref_columns[0])
    return None


def _access_token_hook(
    catalog: Catalog, config: AuditConfig, escaping: set[str]
) -> tuple[str, str] | None:
    """The custom access token hook: from supabase/config.toml, else a function Supabase Auth
    may call (granted to supabase_auth_admin) named like one. Never one that escapes."""
    if config.access_token_hook:
        schema, _, name = config.access_token_hook.partition(".")
        return None if name in escaping else (schema, name)
    hook = next(
        (
            f
            for f in catalog.functions
            if f.granted_to_auth_admin and "access_token" in f.name and "jsonb" in f.arguments
        ),
        None,
    )
    return None if hook is None or hook.name in escaping else (hook.schema, hook.name)


def _skip_reason(table: Table, probe: ProbeConfig, escaping: set[str]) -> str | None:
    if table.qualified_name in probe.skip_tables:
        return "listed in [probe] skip_tables"
    for trigger in table.triggers:
        if trigger.function_name in escaping:
            return (
                f'trigger "{trigger.name}" runs {trigger.function_name}(), which acts outside '
                "the transaction (http, dblink)"
            )
    return None


def _needed(tables: dict[str, Table], exposed: set[str], tenancy: Tenancy) -> set[str]:
    """Tables to fill: the exposed ones; tables of other schemas that hold tenancy (a private
    memberships table that helpers read); and every table their rows point at."""
    needed = exposed | {name for name in tables if tenancy.scope_of(name)}
    frontier = list(needed)
    while frontier:
        for fk in tables[frontier.pop()].foreign_keys:
            if fk.ref_name in tables and fk.ref_name not in needed:
                needed.add(fk.ref_name)
                frontier.append(fk.ref_name)
    return needed


def _step(
    table: Table,
    persona: Persona,
    command: str,
    tenant: str | None,
    target: str,
    scenario: str,
    rows: dict[tuple[str, str | None], str],
    ctx: RecipeContext,
    rng: random.Random,
) -> Step | None:
    owned = table.qualified_name in ctx.tenancy.user_scoped
    if owned:
        label = "row in bob's name" if command == "INSERT" else "row of bob's"
    else:
        label = f"row of tenant {tenant}" if tenant else "synthetic row"
    base = {
        "persona": persona.name,
        "schema": table.schema,
        "table": table.name,
        "command": command,
        "tenant": tenant,
        "scenario": scenario,
        "target_label": label,
    }
    if command == "INSERT":
        # Creating a tenant of your own is not reaching someone else's.
        if persona.logged_in and table.qualified_name == ctx.tenancy.tenant_table:
            return None
        # Into tenant B as yourself; but a user's row is only someone else's in their name.
        owner = persona.name if scenario == CROSS_TENANT else OWNERS[tenant]
        try:
            recipe = build_recipe(
                table,
                key=f"{table.qualified_name}#{persona.name}",
                tenant=tenant,
                owner=owner,
                rows=rows,
                ctx=ctx,
                rng=rng,
                fixture=False,
            )
        except RecipeError:
            return None
        return Step(**base, recipe=recipe)
    if command == "UPDATE":
        column = _updatable_column(table)
        if column is None:
            return None
        return Step(**base, target=target, key=table.primary_key, set_column=column)
    return Step(**base, target=target, key=table.primary_key)


def _updatable_column(table: Table) -> str | None:
    """A column an UPDATE can set to its own value: preferably not a key or a reference."""
    settable = [c for c in table.column_details if not c.generated and c.identity != "a"]
    keys = set(table.primary_key).union(*(fk.columns for fk in table.foreign_keys))
    plain = [c for c in settable if c.name not in keys]
    chosen = (plain or settable or [None])[0]
    return chosen.name if chosen else None

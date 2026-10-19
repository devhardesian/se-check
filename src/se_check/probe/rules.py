"""What the probe's observations mean: findings, one per rule and table.

Pure: tested with hand-made observations, without a database.
"""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Iterable
from dataclasses import dataclass, replace

from se_check.catalog import PRIVILEGES, Catalog, Policy, Table
from se_check.checks.base import Rule, qualified, quote_ident
from se_check.models import Finding, Severity
from se_check.probe.model import (
    ANON_ACCESS,
    CROSS_TENANT,
    CROSS_USER,
    MALLORY,
    OUTSIDER,
    PERSONAS_BY_NAME,
    SELF_ESCALATION,
    TENANT_HOP,
    Observation,
    Outcome,
    ProbePlan,
    Step,
)

PROBE_ANON_ACCESS = Rule(
    id="probe-anon-access",
    title="Rows the anon key reaches (dynamic probe)",
    description=(
        "With --probe: acting as anon inside a rolled-back transaction, se-check read, updated, "
        "deleted or inserted a synthetic row. Critical on tables whose rows belong to a tenant "
        "or a user, and for updates and deletes; medium for inserts and low for reads of other "
        "tables (public data)."
    ),
    max_severity=Severity.CRITICAL,
)

PROBE_CROSS_TENANT_READ = Rule(
    id="probe-cross-tenant-read",
    title="Rows of another tenant that users can read (dynamic probe)",
    description=(
        "With --probe: logged in as a member of tenant A, as a user of no tenant, or as a user "
        "who wrote tenant B into her own user_metadata, se-check read a synthetic row of "
        "tenant B."
    ),
)

PROBE_CROSS_TENANT_WRITE = Rule(
    id="probe-cross-tenant-write",
    title="Rows of another tenant that users can change (dynamic probe)",
    description=(
        "With --probe: logged in as a member of tenant A, or as a user of no tenant, se-check "
        "updated or deleted a synthetic row of tenant B, inserted one into tenant B, or moved a "
        "row of tenant A into tenant B."
    ),
)

PROBE_CROSS_USER_READ = Rule(
    id="probe-cross-user-read",
    title="Rows of another user that users can read (dynamic probe)",
    description=(
        "With --probe: on tables whose rows belong to a user (`notes.user_id`) and no tenant, "
        "logged in as one user, se-check read another user's synthetic row."
    ),
)

PROBE_CROSS_USER_WRITE = Rule(
    id="probe-cross-user-write",
    title="Rows of another user that users can change (dynamic probe)",
    description=(
        "With --probe: on tables whose rows belong to a user and no tenant, logged in as one "
        "user, se-check updated or deleted another user's synthetic row, or inserted one in "
        "their name."
    ),
)

PROBE_SELF_ESCALATION = Rule(
    id="probe-self-escalation",
    title="Privileges users can raise on their own rows (dynamic probe)",
    description=(
        "With --probe: logged in as a member of tenant A, se-check changed a column that decides "
        "privileges (role, is_admin, plan, ...) on her own row, or moved the row that makes her "
        "a member (her profile, her membership) into tenant B."
    ),
)

PROBE_RULES: tuple[Rule, ...] = (
    PROBE_ANON_ACCESS,
    PROBE_CROSS_TENANT_READ,
    PROBE_CROSS_TENANT_WRITE,
    PROBE_CROSS_USER_READ,
    PROBE_CROSS_USER_WRITE,
    PROBE_SELF_ESCALATION,
)

_VERBS = {"SELECT": "read", "INSERT": "insert", "UPDATE": "update", "DELETE": "delete"}


@dataclass(frozen=True)
class _Boundary:
    """A line users must not cross: between tenants, or between users."""

    read: Rule
    write: Rule
    scenarios: tuple[str, ...]
    whose: str
    """`another tenant's`, `other users'`."""
    done: dict[str, str]
    example: str


_TENANTS = _Boundary(
    read=PROBE_CROSS_TENANT_READ,
    write=PROBE_CROSS_TENANT_WRITE,
    scenarios=(CROSS_TENANT, TENANT_HOP),
    whose="another tenant's",
    done={
        "SELECT": "read a synthetic row of tenant B",
        "UPDATE": "updated a synthetic row of tenant B",
        "DELETE": "deleted a synthetic row of tenant B",
        "INSERT": "inserted a row into tenant B",
        TENANT_HOP: "moved a row of tenant A into tenant B",
    },
    example="tenant_id in (select <function returning the caller's tenant ids>())",
)

_USERS = _Boundary(
    read=PROBE_CROSS_USER_READ,
    write=PROBE_CROSS_USER_WRITE,
    scenarios=(CROSS_USER,),
    whose="other users'",
    done={
        "SELECT": "read a synthetic row belonging to bob",
        "UPDATE": "updated a synthetic row belonging to bob",
        "DELETE": "deleted a synthetic row belonging to bob",
        "INSERT": "inserted a row in bob's name",
    },
    example="{owner} = (select auth.uid())",
)

_WHO = {
    "alice": "a member of tenant A",
    "outsider": "a user who belongs to no tenant",
    "mallory": (
        "a user who wrote tenant B into her own user_metadata, as anyone can with "
        "supabase.auth.updateUser()"
    ),
}


def interpret(
    catalog: Catalog, plan: ProbePlan, observations: Iterable[Observation]
) -> list[Finding]:
    """Findings from what the personas managed to do. Denials and filtered rows are the
    expected outcomes; inconclusive steps belong to the coverage, not here."""
    allowed: dict[str, list[Step]] = defaultdict(list)
    for observation in observations:
        if observation.outcome is Outcome.ALLOWED:
            allowed[observation.step.table_name].append(observation.step)

    findings: list[Finding] = []
    for table_name in sorted(allowed):
        table = catalog.table(*table_name.split(".", 1))
        if table is None:
            continue
        steps = allowed[table_name]
        scope = plan.tenancy.scope_of(table_name)
        anon = [s for s in steps if s.scenario == ANON_ACCESS]
        if anon:
            owned = table_name in plan.tenancy.user_scoped
            findings.append(_anon_access(catalog, table, anon, scope, owned))
        # What anon can do, any logged-in user can too: one finding is enough.
        anon_commands = {s.command for s in anon}
        for boundary in (_TENANTS, _USERS):
            crossing = [
                s
                for s in steps
                if s.scenario in boundary.scenarios and s.command not in anon_commands
            ]
            reads = [s for s in crossing if s.command == "SELECT"]
            writes = [s for s in crossing if s.command != "SELECT"]
            if reads:
                findings.append(_crossing(catalog, table, boundary, reads, scope, write=False))
            if writes:
                findings.append(_crossing(catalog, table, boundary, writes, scope, write=True))
        raised = [s for s in steps if s.scenario == SELF_ESCALATION]
        if raised:
            findings.append(_self_escalation(catalog, plan, table, raised))
    return findings


# Static checks that describe the same hole a probe rule shows, when they name the same table.
_CONFIRMS = {
    PROBE_ANON_ACCESS.id: {"rls-disabled", "permissive-policy"},
    PROBE_CROSS_TENANT_READ.id: {"rls-disabled", "permissive-policy", "user-metadata-auth"},
    PROBE_CROSS_TENANT_WRITE.id: {"rls-disabled", "permissive-policy", "user-metadata-auth"},
    PROBE_CROSS_USER_READ.id: {"rls-disabled", "permissive-policy"},
    PROBE_CROSS_USER_WRITE.id: {"rls-disabled", "permissive-policy"},
    PROBE_SELF_ESCALATION.id: set(),  # no static check sees it
}


def link_confirmations(probe: Iterable[Finding], static: Iterable[Finding]) -> list[Finding]:
    """Mark probe findings that confirm a static finding about the same hole and table."""
    checks_by_object: dict[str, set[str]] = defaultdict(set)
    for finding in static:
        checks_by_object[finding.object].add(finding.check)
    linked = []
    for finding in probe:
        related = _CONFIRMS.get(finding.check, set())
        confirmed = sorted(checks_by_object.get(finding.object, set()) & related)
        if confirmed:
            names = ", ".join(f"[{check}]" for check in confirmed)
            finding = replace(
                finding,
                detail=f"{finding.detail} This confirms {names} on the same table.",
                evidence={**finding.evidence, "confirms": ", ".join(confirmed)},
            )
        linked.append(finding)
    return linked


# --- the findings -----------------------------------------------------------------------------


def _anon_access(
    catalog: Catalog, table: Table, steps: list[Step], scope: str | None, owned: bool
) -> Finding:
    ordered = _commands(steps)
    if scope is not None:
        severity = Severity.CRITICAL
    else:
        severity = max(_ANON_SEVERITY[cmd] for cmd in ordered)
    whose, into = (
        (" belonging to bob", " in bob's name")
        if owned
        else (" of tenant B", " into tenant B")
        if scope
        else ("", "")
    )
    done = {
        "SELECT": f"read a synthetic row{whose}",
        "UPDATE": f"updated a synthetic row{whose}",
        "DELETE": f"deleted a synthetic row{whose}",
        "INSERT": f"inserted a row{into}",
    }
    detail = [
        "Acting as anon, as a request carrying only the anon key would, inside a transaction it "
        f"rolled back, se-check {_and([done[cmd] for cmd in ordered])}."
    ]
    if scope is not None:
        kind = "user" if owned else "tenant"
        detail.append(
            f"The rows belong to a {kind} ({scope}), and the anon key ships with your frontend: "
            f"anyone reaches every {kind}'s rows."
        )
    policies = _policies(catalog, table, "anon", ordered)
    if not table.rls_enabled:
        detail.append("Row Level Security is disabled on the table.")
        remediation = _enable_rls(table)
    else:
        if policies:
            detail.append(f"Policies that apply to anon here: {_names(policies)}.")
        remediation = (
            "Restrict the policies that let anon through to `authenticated` and tie them to the "
            "caller, or drop them; if the data is public on purpose, accept the finding.\n"
            + "".join(f"-- {_policy_ref(p)}\n" for p in policies)
        ).rstrip("\n")
    return Finding(
        check=PROBE_ANON_ACCESS.id,
        severity=severity,
        object=table.qualified_name,
        title=f"The anon key can {_and([_VERBS[cmd] for cmd in ordered])} rows",
        detail=" ".join(detail),
        remediation=remediation,
        evidence=_evidence(steps, policies, personas=False),
    )


_ANON_SEVERITY = {
    "SELECT": Severity.LOW,
    "INSERT": Severity.MEDIUM,
    "UPDATE": Severity.CRITICAL,
    "DELETE": Severity.CRITICAL,
}


def _crossing(
    catalog: Catalog,
    table: Table,
    boundary: _Boundary,
    steps: list[Step],
    scope: str | None,
    *,
    write: bool,
) -> Finding:
    rule = boundary.write if write else boundary.read
    ordered = _commands(steps)
    actions = list(dict.fromkeys(_action(s) for s in steps))
    actions.sort(key=lambda a: [*PRIVILEGES, TENANT_HOP].index(a))
    who = _who(steps) if boundary is _TENANTS else "one user"
    filtered = (
        ", filtered on the primary key as the Data API would" if actions != ["INSERT"] else ""
    )
    detail = [
        f"Logged in as {who}, inside a transaction it rolled back, se-check "
        f"{_and([boundary.done[a] for a in actions])}{filtered}."
    ]
    if scope:
        detail.append(
            f"The rows belong to a {'tenant' if boundary is _TENANTS else 'user'} ({scope})."
        )
    policies = _policies(catalog, table, "authenticated", ordered)
    if policies:
        detail.append(f"Policies for authenticated: {_names(policies)}.")
    forged = {step.persona for step in steps} == {MALLORY.name}
    if forged:
        detail.append(
            "Only she got through: the policies take the tenant from user_metadata, which every "
            "user edits."
        )
    clauses = ["using"] if not write else []
    if {"UPDATE", "DELETE"} & set(ordered):
        clauses.append("using")
    if {"INSERT", "UPDATE"} & set(ordered):
        clauses.append("with check")
    verbs = [_VERBS[cmd] for cmd in ordered]
    remediation = _tie_policies(
        table, policies, list(dict.fromkeys(clauses)), boundary.example.format(owner=scope)
    )
    if forged:
        remediation = (
            "Take the tenant from a table users cannot write (memberships), or from app_metadata, "
            f"which only the service role changes.\n{remediation}"
        )
    return Finding(
        check=rule.id,
        severity=Severity.HIGH,
        object=table.qualified_name,
        title=f"Users can {_and(verbs)} {boundary.whose} rows",
        detail=" ".join(detail),
        remediation=remediation,
        evidence=_evidence(steps, policies),
    )


def _self_escalation(catalog: Catalog, plan: ProbePlan, table: Table, steps: list[Step]) -> Finding:
    first = {}
    for step in steps:
        first.setdefault(step.set_column, step)
    columns = list(first)
    settings = _and([f"{column} to {first[column].value_label}" for column in columns])
    if table.qualified_name == plan.tenancy.tenant_table:
        row = "her own tenant's row"
    else:
        row = "her own row"
    detail = [
        f"Logged in as {_WHO['alice']}, inside a transaction it rolled back, se-check updated "
        f"{row}, setting {settings}."
    ]
    if any(step.value_label == "<tenant B>" for step in steps):
        detail.append("That row says which tenant she belongs to: now it is tenant B.")
    policies = _policies(catalog, table, "authenticated", ["UPDATE"])
    if policies:
        detail.append(f"UPDATE policies for authenticated: {_names(policies)}.")
    name = qualified(table.schema, table.name)
    remediation = (
        f"revoke update on {name} from authenticated;\n"
        f"grant update (<the columns users may change>) on {name} to authenticated;\n"
        f"-- then change {_and(columns)} only server-side: the service role, an admin function, "
        "or a trigger that rejects other changes"
    )
    return Finding(
        check=PROBE_SELF_ESCALATION.id,
        severity=Severity.HIGH,
        object=table.qualified_name,
        title=f"Users can set their own {_and(columns)}",
        detail=" ".join(detail),
        remediation=remediation,
        evidence={**_evidence(steps, policies), "columns": ", ".join(columns)},
    )


# --- helpers ----------------------------------------------------------------------------------


def _action(step: Step) -> str:
    return TENANT_HOP if step.scenario == TENANT_HOP else step.command


def _commands(steps: Iterable[Step]) -> list[str]:
    commands = {step.command for step in steps}
    return [cmd for cmd in PRIVILEGES if cmd in commands]


def _policies(catalog: Catalog, table: Table, role: str, commands: list[str]) -> list[Policy]:
    return [
        policy
        for policy in catalog.policies
        if policy.schema == table.schema
        and policy.table == table.name
        and policy.permissive
        and policy.applies_to([role])
        and set(policy.commands) & set(commands)
    ]


def _enable_rls(table: Table) -> str:
    return (
        f"alter table {qualified(table.schema, table.name)} enable row level security;\n"
        "-- then add policies for the access you actually want"
    )


def _tie_policies(table: Table, policies: list[Policy], clauses: list[str], example: str) -> str:
    name = qualified(table.schema, table.name)
    if not table.rls_enabled:
        lines = [_enable_rls(table)]
    else:
        condition = " ".join(f"{clause} (<condition>)" for clause in clauses)
        lines = [f"alter policy {quote_ident(p.name)} on {name} {condition};" for p in policies]
        lines = lines or [f"-- review the policies on {name} that let these rows through"]
    lines.append(f"-- where <condition> ties rows to the caller, e.g. {example}")
    return "\n".join(lines)


def _policy_ref(policy: Policy) -> str:
    return f'policy "{policy.name}" ({policy.command}, to {", ".join(policy.roles)})'


def _names(policies: list[Policy]) -> str:
    return ", ".join(f'"{p.name}"' for p in policies)


def _who(steps: Iterable[Step]) -> str:
    personas = {step.persona for step in steps}
    if OUTSIDER.name in personas:
        personas.discard(MALLORY.name)  # any logged-in user gets through: forging adds nothing
    return ", and as ".join(_WHO.get(p, PERSONAS_BY_NAME[p].describe()) for p in sorted(personas))


def _evidence(
    steps: list[Step], policies: list[Policy], *, personas: bool = True
) -> dict[str, str]:
    tried = list(dict.fromkeys(describe_statement(step) for step in _in_order(steps)))
    evidence = {"commands": ", ".join(_commands(steps)), "tried": "; ".join(tried)}
    if personas:
        evidence["personas"] = ", ".join(sorted({step.persona for step in steps}))
    if policies:
        evidence["policies"] = ", ".join(p.name for p in policies)
    return evidence


def _in_order(steps: list[Step]) -> list[Step]:
    return sorted(steps, key=lambda s: (PRIVILEGES.index(s.command), s.scenario == TENANT_HOP))


def describe_statement(step: Step) -> str:
    """The statement a step ran, with placeholders instead of values."""
    table = qualified(step.schema, step.table)
    row = f"<{step.target_label}>"
    where = " and ".join(f"{quote_ident(c)} = {row}" for c in step.key)
    if step.command == "SELECT":
        return f"select exists(select 1 from {table} where {where})"
    if step.command == "UPDATE":
        column = quote_ident(step.set_column or "")
        value = step.value_label or column
        return f"update {table} set {column} = {value} where {where}"
    if step.command == "DELETE":
        return f"delete from {table} where {where}"
    return f"insert into {table} a {step.target_label}"


def _and(words: list[str]) -> str:
    return words[0] if len(words) == 1 else ", ".join(words[:-1]) + " and " + words[-1]

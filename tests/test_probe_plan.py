"""The probe's planner: tenancy, synthetic rows and steps, worked out from hand-made catalogs."""

from __future__ import annotations

import random
import uuid

import pytest
from factories import catalog, col, fk, function, policy, table

from se_check.catalog import AuthUserTrigger, TableTrigger
from se_check.config import AuditConfig, ProbeConfig
from se_check.probe.fixtures import synthetic_value
from se_check.probe.model import NULL, ExistingRow, RowValue, Text, UserId
from se_check.probe.plan import escaping_functions, plan_probe
from se_check.probe.tenancy import infer_tenancy

READ_ONLY = {"anon": frozenset(), "authenticated": frozenset({"SELECT"})}


def tenants():
    return table(
        "tenants",
        details=(col("id", "uuid", not_null=True, default=True), col("name", not_null=True)),
    )


def memberships():
    return table(
        "memberships",
        details=(
            col("user_id", "uuid", not_null=True),
            col("tenant_id", "uuid", not_null=True),
            col("role", not_null=True, default=True),
        ),
        primary_key=("user_id", "tenant_id"),
        foreign_keys=(fk("user_id", "auth.users"), fk("tenant_id", "public.tenants")),
    )


def projects():
    return table(
        "projects",
        details=(
            col("id", "uuid", not_null=True, default=True),
            col("tenant_id", "uuid", not_null=True),
            col("name", not_null=True),
        ),
        foreign_keys=(fk("tenant_id", "public.tenants"),),
    )


def comments():
    return table(
        "comments",
        details=(
            col("id", "int8", not_null=True, identity="a"),
            col("project_id", "uuid", not_null=True),
            col("body", not_null=True),
        ),
        foreign_keys=(fk("project_id", "public.projects"),),
    )


def profiles():
    return table(
        "profiles",
        details=(
            col("id", "uuid", not_null=True),
            col("tenant_id", "uuid"),
            col("role", not_null=True, default=True),
        ),
        foreign_keys=(fk("id", "auth.users"), fk("tenant_id", "public.tenants")),
    )


def plans():
    return table("plans", details=(col("id", not_null=True), col("price", "int4", not_null=True)))


def app(*extra, functions=(), triggers=()):
    return catalog(
        tables=[tenants(), memberships(), projects(), comments(), profiles(), plans(), *extra],
        functions=functions,
        triggers=triggers,
    )


def plan(cat=None, probe=None, **config):
    return plan_probe(cat or app(), AuditConfig(**config), probe, random.Random(0))


def fixture(probe_plan, key):
    return next(r for r in probe_plan.fixtures if r.key == key)


def steps(probe_plan, table_name, persona=None):
    return [
        (s.persona, s.command)
        for s in probe_plan.steps
        if s.table_name == table_name and (persona is None or s.persona == persona)
    ]


# --- tenancy ----------------------------------------------------------------------------------


def test_tenant_table_is_the_one_tenant_columns_reference():
    tenancy = infer_tenancy(app(), AuditConfig())
    assert tenancy.tenant_table == "public.tenants"
    assert tenancy.tenant_key == "id"
    assert set(tenancy.scoped) == {
        "public.tenants",
        "public.memberships",
        "public.projects",
        "public.profiles",
        "public.comments",  # through its NOT NULL foreign key to projects
    }
    assert tenancy.scoped["public.comments"] == "project_id -> public.projects"
    assert tenancy.describe() == "tenants in public.tenants, 4 tenant-scoped tables"


def test_nullable_reference_to_a_tenant_table_does_not_make_a_table_tenant_scoped():
    notes = table(
        "notes",
        details=(col("id", "uuid", not_null=True), col("project_id", "uuid")),
        foreign_keys=(fk("project_id", "public.projects"),),
    )
    assert "public.notes" not in infer_tenancy(app(notes), AuditConfig()).scoped


def test_no_tenant_columns_means_no_tenancy():
    tenancy = infer_tenancy(catalog(tables=[plans()]), AuditConfig())
    assert tenancy.scoped == {}
    assert tenancy.describe() == "no tenant-scoped tables found"


def test_tenant_column_without_tenant_table_gets_made_up_tenant_ids():
    events = table(
        "events", details=(col("id", "uuid", not_null=True), col("org_id", "uuid", not_null=True))
    )
    probe_plan = plan(catalog(tables=[events]))
    assert probe_plan.tenancy.tenant_table is None
    a, b = probe_plan.tenant_ids["A"], probe_plan.tenant_ids["B"]
    assert isinstance(a, Text) and isinstance(b, Text) and a != b
    assert dict(fixture(probe_plan, "public.events@B").values)["org_id"] == b


# --- synthetic rows ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("column", "check"),
    [
        (col("t"), lambda v: v.startswith("se-check-")),
        (col("v", "varchar", max_length=5), lambda v: len(v) == 5),
        (col("u", "uuid"), lambda v: uuid.UUID(v).version == 4),
        (col("s", "int2"), lambda v: 1 <= int(v) <= 32767),
        (col("i", "int8"), lambda v: int(v) >= 1),
        (col("n", "numeric"), lambda v: v == "1"),
        (col("b", "bool"), lambda v: v == "false"),
        (col("ts", "timestamptz"), lambda v: v == "now"),
        (col("d", "interval"), lambda v: v == "0"),
        (col("ip", "inet"), lambda v: v == "192.0.2.1"),
        (col("a", "text[]"), lambda v: v == "{}"),
        (col("j", "jsonb"), lambda v: v == "{}"),
        (col("e", "mood", labels=("ok", "bad")), lambda v: v == "ok"),
    ],
)
def test_synthetic_values_by_type(column, check):
    assert check(synthetic_value(column, random.Random(0)))


def test_no_synthetic_value_for_unusual_types():
    assert synthetic_value(col("p", "point"), random.Random(0)) is None


def test_rows_take_their_tenant_from_the_tenant_rows():
    probe_plan = plan()
    recipe = fixture(probe_plan, "public.projects@B")
    values = dict(recipe.values)
    assert values["tenant_id"] == RowValue("public.tenants@B", "id")
    assert isinstance(values["name"], Text)
    assert "id" not in values  # left to its default, read back
    assert recipe.returning == ("id",)
    assert recipe.conflict == ()


def test_references_point_at_rows_of_the_same_tenant():
    values = dict(fixture(plan(), "public.comments@A").values)
    assert values["project_id"] == RowValue("public.projects@A", "id")
    assert "id" not in values  # identity column


def test_rows_keyed_by_a_user_belong_to_the_owner_and_are_upserted():
    probe_plan = plan()
    membership = fixture(probe_plan, "public.memberships@A")
    assert dict(membership.values)["user_id"] == UserId("alice")
    assert membership.conflict == ("user_id", "tenant_id")
    profile = fixture(probe_plan, "public.profiles@B")
    assert dict(profile.values)["id"] == UserId("bob")
    assert dict(profile.values)["tenant_id"] == RowValue("public.tenants@B", "id")
    assert profile.conflict == ("id",)  # a signup trigger may have made it already


def test_fixtures_come_after_the_rows_they_point_at():
    keys = [recipe.key for recipe in plan().fixtures]
    assert keys.index("public.tenants@B") < keys.index("public.projects@B")
    assert keys.index("public.projects@B") < keys.index("public.comments@B")
    assert "public.plans" in keys  # not tenant-scoped: a single row


def test_configured_values_win():
    probe = ProbeConfig(values={"public.plans": {"price": "100", "id": "pro"}})
    values = dict(fixture(plan(probe=probe), "public.plans").values)
    assert values == {"id": Text("pro"), "price": Text("100")}


def test_tables_without_a_possible_row_are_skipped_with_the_reason():
    shapes = table(
        "shapes", details=(col("id", "uuid", not_null=True), col("p", "point", not_null=True))
    )
    archived = table(
        "archived",
        details=(col("id", "uuid", not_null=True), col("owner", "uuid", not_null=True)),
        foreign_keys=(fk("owner", "private.accounts"),),
    )
    skipped = {s.table: s.reason for s in plan(app(shapes, archived)).skipped}
    assert "cannot make up a value for p (point)" in skipped["public.shapes"]
    assert '[probe.values."public.shapes"]' in skipped["public.shapes"]
    assert (
        skipped["public.archived"]
        == "needs a row of private.accounts, in a schema se-check leaves alone"
    )


def test_tables_without_primary_key_are_skipped_if_the_api_reaches_them():
    loose = table("loose", details=(col("x"),))
    hidden = table("hidden", details=(col("x"),), privileges={})
    skipped = {s.table: s.reason for s in plan(app(loose, hidden)).skipped}
    assert skipped == {"public.loose": "no primary key to address its rows by"}


def test_skip_tables_setting():
    probe_plan = plan(probe=ProbeConfig(skip_tables=("public.plans",)))
    assert {s.table: s.reason for s in probe_plan.skipped} == {
        "public.plans": "listed in [probe] skip_tables"
    }
    assert not steps(probe_plan, "public.plans")


def test_skips_name_the_table_whose_row_they_needed():
    shapes = table(
        "shapes",
        details=(
            col("id", "uuid", not_null=True),
            col("tenant_id", "uuid", not_null=True),
            col("p", "point", not_null=True),
        ),
        foreign_keys=(fk("tenant_id", "public.tenants"),),
    )
    notes = table(
        "shape_notes",
        details=(col("id", "uuid", not_null=True), col("shape_id", "uuid", not_null=True)),
        foreign_keys=(fk("shape_id", "public.shapes"),),
    )
    skipped = {s.table: s for s in plan(app(shapes, notes)).skipped}
    assert skipped["public.shapes"].cause is None
    assert skipped["public.shape_notes"].cause == "public.shapes"


# --- references whose row is missing ----------------------------------------------------------


def statuses(*details):
    """Reference data in a private schema: no tenant, no owner, no API access."""
    return table(
        "statuses",
        schema="private",
        privileges={},
        details=(col("code", not_null=True), *details),
        primary_key=("code",),
    )


def tickets(*, status_not_null=True):
    return table(
        "tickets",
        details=(
            col("id", "uuid", not_null=True, default=True),
            col("tenant_id", "uuid", not_null=True),
            col("status", not_null=status_not_null),
            col("project_id", "uuid"),
        ),
        foreign_keys=(
            fk("tenant_id", "public.tenants"),
            fk("status", "private.statuses", ("code",)),
            fk("project_id", "public.projects"),
        ),
    )


def _tickets_plan(*, status_not_null=True, status_details=()):
    tables = [tenants(), projects(), tickets(status_not_null=status_not_null)]
    return plan(catalog(tables=tables, support=[statuses(*status_details)]))


EXISTING_STATUS = ExistingRow("private", "statuses", ("code",), "code", "text")


def test_references_take_a_stand_in_when_their_row_is_missing():
    values = dict(fixture(_tickets_plan(), "public.tickets@B").values)
    # Reference data: a row the table already holds, picked by the database.
    assert values["status"] == RowValue("private.statuses", "code", EXISTING_STATUS)
    # May be NULL: NULL, whatever it points at.
    assert values["project_id"] == RowValue("public.projects@B", "id", NULL)
    # The tenant column says whose the row is: no stand-in.
    assert values["tenant_id"] == RowValue("public.tenants@B", "id")

    nullable = dict(fixture(_tickets_plan(status_not_null=False), "public.tickets@B").values)
    assert nullable["status"] == RowValue("private.statuses", "code", NULL)


def test_no_existing_rows_of_tenant_data_or_for_keys():
    # comments.project_id is NOT NULL and projects are tenant data.
    values = dict(fixture(plan(), "public.comments@B").values)
    assert values["project_id"] == RowValue("public.projects@B", "id")

    tags = table(
        "ticket_tags",
        details=(col("ticket_id", "uuid", not_null=True), col("tag", not_null=True)),
        primary_key=("ticket_id", "tag"),
        foreign_keys=(fk("tag", "private.statuses", ("code",)),),
    )
    probe_plan = plan(catalog(tables=[tags], support=[statuses()]))
    # Steps address rows by their primary key: se-check would have to read the value.
    assert dict(fixture(probe_plan, "public.ticket_tags").values)["tag"] == RowValue(
        "private.statuses", "code"
    )


def test_reference_data_without_a_synthetic_row_lends_an_existing_one():
    probe_plan = _tickets_plan(status_details=(col("shape", "point", not_null=True),))
    assert "private.statuses" not in [recipe.key for recipe in probe_plan.fixtures]
    assert dict(fixture(probe_plan, "public.tickets@B").values)["status"] == EXISTING_STATUS
    assert "public.tickets" not in {s.table for s in probe_plan.skipped}


def test_coverage_is_measured_on_the_tables_personas_can_try():
    lookup = table(  # logged-in users read it, and it belongs to no one: nothing to cross
        "lookup",
        details=(col("id", "uuid", not_null=True),),
        privileges={"anon": frozenset(), "authenticated": frozenset({"SELECT"})},
    )
    hidden = table("hidden", details=(col("id", "uuid", not_null=True),), privileges={})
    probe_plan = plan(
        app(lookup, hidden), probe=ProbeConfig(skip_tables=("public.plans", "public.hidden"))
    )
    assert set(probe_plan.targets) == {
        "public.tenants",
        "public.memberships",
        "public.projects",
        "public.comments",
        "public.profiles",
    }
    assert probe_plan.left_out == ("public.plans",)


# --- steps ------------------------------------------------------------------------------------


def test_attackers_try_tenant_b_rows_of_tenant_scoped_tables():
    probe_plan = plan()
    tried = steps(probe_plan, "public.projects")
    for persona in ("alice", "outsider", "anon"):
        for command in ("SELECT", "INSERT", "UPDATE", "DELETE"):
            assert (persona, command) in tried
    assert not steps(probe_plan, "public.projects", "bob")  # the victim
    select = next(
        s for s in probe_plan.steps if s.table_name == "public.projects" and s.persona == "alice"
    )
    assert select.target == "public.projects@B"
    assert select.key == ("id",)


def test_only_anon_tries_tables_that_are_not_tenant_scoped():
    assert {persona for persona, _ in steps(plan(), "public.plans")} == {"anon"}


def test_steps_follow_the_privileges_the_roles_hold():
    readonly_docs = table(
        "readonly_docs",
        details=(col("id", "uuid", not_null=True), col("tenant_id", "uuid", not_null=True)),
        foreign_keys=(fk("tenant_id", "public.tenants"),),
        privileges=READ_ONLY,
    )
    probe_plan = plan(app(readonly_docs))
    assert steps(probe_plan, "public.readonly_docs") == [
        ("alice", "SELECT"),
        ("outsider", "SELECT"),
    ]


def test_logged_in_users_may_create_tenants_of_their_own():
    tried = steps(plan(), "public.tenants")
    assert ("alice", "INSERT") not in tried
    assert ("alice", "SELECT") in tried
    assert ("anon", "INSERT") in tried


def test_inserts_claim_the_actor_as_owner_and_tenant_b():
    probe_plan = plan()
    insert = next(
        s
        for s in probe_plan.steps
        if s.table_name == "public.memberships" and s.persona == "alice" and s.command == "INSERT"
    )
    values = dict(insert.recipe.values)
    assert values["user_id"] == UserId("alice")  # alice adding herself to tenant B
    assert values["tenant_id"] == RowValue("public.tenants@B", "id")
    assert insert.recipe.returning == () and insert.recipe.conflict == ()


def test_updates_set_a_plain_column_to_itself():
    update = next(
        s
        for s in plan().steps
        if s.table_name == "public.projects" and s.persona == "alice" and s.command == "UPDATE"
    )
    assert update.set_column == "name"


def test_one_synthetic_user_per_logged_in_persona():
    users = plan().users
    assert set(users) == {"alice", "bob", "outsider", "mallory"}
    assert len(set(users.values())) == 4


# --- what a rollback cannot undo --------------------------------------------------------------


def _trigger_table(function_name):
    return table(
        "events",
        details=(col("id", "uuid", not_null=True),),
        triggers=(TableTrigger("notify", "public", function_name),),
    )


def test_tables_whose_triggers_act_outside_the_transaction_are_skipped():
    notify = function("notify_slack", body="begin perform http_post('https://x', '{}'); end")
    skipped = {
        s.table: s.reason
        for s in plan(app(_trigger_table("notify_slack"), functions=[notify])).skipped
    }
    assert "notify_slack()" in skipped["public.events"]


def test_pg_net_requests_roll_back_with_the_transaction():
    queue = function("queue_webhook", body="begin perform net.http_post('https://x'); end")
    probe_plan = plan(app(_trigger_table("queue_webhook"), functions=[queue]))
    assert not probe_plan.skipped


def test_escaping_calls_are_followed_through_helpers():
    helper = function("send", body="select extensions.http_get('https://x')")
    caller = function("on_insert", body="begin perform send(); end")
    unrelated = function("audit", body="begin perform net.http_get('https://x'); end")
    assert escaping_functions(catalog(functions=[helper, caller, unrelated])) == {
        "send",
        "on_insert",
    }


def test_escaping_signup_trigger_blocks_the_whole_probe():
    hook = function("sync_crm", body="begin perform dblink_exec('crm', 'insert ...'); end")
    trigger = AuthUserTrigger("on_signup", "public", "sync_crm")
    probe_plan = plan(app(functions=[hook], triggers=[trigger]))
    assert probe_plan.blocked.startswith('a trigger on auth.users, "on_signup", runs sync_crm()')


# --- rows owned by a user ---------------------------------------------------------------------


def notes():
    return table(
        "notes",
        details=(
            col("id", "uuid", not_null=True, default=True),
            col("user_id", "uuid", not_null=True),
            col("body", not_null=True),
        ),
        foreign_keys=(fk("user_id", "auth.users"),),
    )


def drafts():
    """A reference to a user that may be NULL says who wrote it, not whose it is."""
    return table(
        "drafts",
        details=(col("id", "uuid", not_null=True), col("created_by", "uuid")),
        foreign_keys=(fk("created_by", "auth.users"),),
    )


def test_tables_of_rows_owned_by_a_user():
    tenancy = infer_tenancy(app(notes(), drafts()), AuditConfig())
    assert tenancy.user_scoped == {"public.notes": "user_id"}
    assert "public.profiles" not in tenancy.user_scoped  # tenant-scoped wins
    assert tenancy.describe().endswith("; 1 table of rows owned by a user")


def test_alice_and_bob_each_own_a_row():
    probe_plan = plan(app(notes()))
    assert dict(fixture(probe_plan, "public.notes@A").values)["user_id"] == UserId("alice")
    assert dict(fixture(probe_plan, "public.notes@B").values)["user_id"] == UserId("bob")


def test_users_try_each_others_rows():
    probe_plan = plan(app(notes()))
    tried = [s for s in probe_plan.steps if s.table_name == "public.notes"]
    cross = [s for s in tried if s.scenario == "cross-user"]
    assert {s.persona for s in cross} == {"alice", "outsider"}
    assert {s.target for s in cross if s.target} == {"public.notes@B"}
    insert = next(s for s in cross if s.command == "INSERT")
    assert dict(insert.recipe.values)["user_id"] == UserId("bob")  # a row in bob's name
    assert insert.target_label == "row in bob's name"
    assert {s.persona for s in tried if s.scenario == "anon"} == {"anon"}


# --- mallory: tenant B written into her own user_metadata -------------------------------------


def _metadata_policy():
    return policy(
        "projects", using="tenant_id = ((auth.jwt() -> 'user_metadata') ->> 'tenant_id')::uuid"
    )


def test_mallory_tries_tenant_rows_when_policies_trust_user_metadata():
    trusting = catalog(tables=app().tables, policies=[_metadata_policy()])
    probe_plan = plan(trusting)
    assert probe_plan.inferred_claims == {"user_metadata": {"tenant_id": "{tenant}"}}
    assert ("mallory", "SELECT") in steps(probe_plan, "public.projects")
    assert not steps(probe_plan, "public.notes", "mallory")


def test_mallory_stays_home_otherwise():
    assert not [s for s in plan().steps if s.persona == "mallory"]


# --- alice on her own rows --------------------------------------------------------------------


def _own(probe_plan, table_name):
    return [
        (s.scenario, s.set_column, s.value_label)
        for s in probe_plan.steps
        if s.table_name == table_name and s.target and s.target.endswith("@A")
    ]


def test_alice_tries_to_raise_her_own_role():
    own = _own(plan(), "public.profiles")
    assert ("self-escalation", "role", "'admin'") in own
    assert ("self-escalation", "role", "'owner'") in own
    # Her profile says which tenant she is in: moving it is joining tenant B.
    assert ("self-escalation", "tenant_id", "<tenant B>") in own


def test_moving_a_row_to_another_tenant_is_a_tenant_hop():
    probe_plan = plan()
    assert _own(probe_plan, "public.projects") == [("tenant-hop", "tenant_id", "<tenant B>")]
    hop = next(
        s
        for s in probe_plan.steps
        if s.scenario == "tenant-hop" and s.table_name == "public.projects"
    )
    assert hop.value == RowValue("public.tenants@B", "id")
    assert hop.target == "public.projects@A"
    # Through the reference that makes the row tenant-scoped.
    assert _own(probe_plan, "public.comments") == [("tenant-hop", "project_id", "<tenant B>")]
    # The tenant table has no tenant to move to.
    assert not [s for s in _own(probe_plan, "public.tenants") if s[0] == "tenant-hop"]


def test_privilege_columns_by_type_and_configuration():
    accounts = table(
        "accounts",
        details=(
            col("id", "uuid", not_null=True),
            col("user_id", "uuid", not_null=True),
            col("is_admin", "bool", not_null=True, default=True),
            col("tier", default=True),
            col("level", "mood", labels=("member", "manager", "owner")),
            col("clearance", "int4"),
            col("nickname"),
        ),
        foreign_keys=(fk("user_id", "auth.users"),),
    )
    probe = ProbeConfig(privilege_columns=("level", "Clearance"))
    own = {
        (column, label) for _, column, label in _own(plan(app(accounts), probe), "public.accounts")
    }
    assert own == {
        ("is_admin", "'true'"),
        ("tier", "'enterprise'"),
        ("tier", "'pro'"),
        ("level", "'manager'"),
        ("level", "'owner'"),
        ("clearance", "'2147483647'"),
    }


def test_only_alices_own_rows_are_escalated():
    # Projects have no owner: a `plan` column there is the tenant's business, not hers.
    projects_with_plan = table(
        "projects",
        details=(*projects().column_details, col("plan", default=True)),
        foreign_keys=projects().foreign_keys,
    )
    tables = [t for t in app().tables if t.name != "projects"]
    own = _own(plan(catalog(tables=[*tables, projects_with_plan])), "public.projects")
    assert [s for s in own if s[0] == "self-escalation"] == []


def test_her_tenants_plan_counts_as_her_own():
    tenants_with_plan = table(
        "tenants", details=(*tenants().column_details, col("plan", not_null=True, default=True))
    )
    tables = [t for t in app().tables if t.name != "tenants"]
    own = _own(plan(catalog(tables=[tenants_with_plan, *tables])), "public.tenants")
    assert ("self-escalation", "plan", "'enterprise'") in own


# --- the custom access token hook -------------------------------------------------------------


def test_access_token_hook_from_config_or_grant():
    granted = function("custom_access_token_hook", arguments="event jsonb", auth_admin=True)
    assert plan(app(functions=[granted])).access_token_hook == (
        "public",
        "custom_access_token_hook",
    )
    assert plan(app()).access_token_hook is None
    configured = plan(app(), access_token_hook="private.claims")
    assert configured.access_token_hook == ("private", "claims")


def test_access_token_hook_that_escapes_is_not_called():
    hook = function(
        "custom_access_token_hook",
        arguments="event jsonb",
        auth_admin=True,
        body="begin perform http_post('https://x', '{}'); return event; end",
    )
    assert plan(app(functions=[hook])).access_token_hook is None


# --- tables the API does not expose -----------------------------------------------------------


def _private_tenancy():
    orgs = table(
        "orgs",
        schema="private",
        privileges={},
        details=(col("id", "uuid", not_null=True, default=True), col("name", not_null=True)),
    )
    members = table(
        "org_members",
        schema="private",
        privileges={},
        details=(col("user_id", "uuid", not_null=True), col("org_id", "uuid", not_null=True)),
        foreign_keys=(fk("user_id", "auth.users"), fk("org_id", "private.orgs")),
    )
    cards = table(
        "cards",
        details=(
            col("id", "uuid", not_null=True, default=True),
            col("org_id", "uuid", not_null=True),
            col("title", not_null=True),
        ),
        foreign_keys=(fk("org_id", "private.orgs"),),
    )
    log = table(
        "card_log",
        details=(col("org_id", "uuid", not_null=True), col("event", not_null=True)),
        foreign_keys=(fk("org_id", "private.orgs"),),
    )
    return catalog(tables=[cards, log], support=[orgs, members])


def test_tenancy_can_live_in_a_private_schema():
    probe_plan = plan(_private_tenancy())
    assert probe_plan.tenancy.tenant_table == "private.orgs"
    keys = [recipe.key for recipe in probe_plan.fixtures]
    # The private tables get rows: membership helpers read them.
    assert {"private.orgs@A", "private.orgs@B", "private.org_members@A"} <= set(keys)
    assert dict(fixture(probe_plan, "private.org_members@A").values)["user_id"] == UserId("alice")
    assert keys.index("private.orgs@B") < keys.index("public.cards@B")
    # Only what the API exposes is tried.
    assert {s.table_name for s in probe_plan.steps} == {"public.cards"}


def test_tables_without_primary_key_still_get_rows():
    probe_plan = plan(_private_tenancy())
    assert "public.card_log@A" in [recipe.key for recipe in probe_plan.fixtures]
    assert {s.table: s.reason for s in probe_plan.skipped} == {
        "public.card_log": "no primary key to address its rows by"
    }

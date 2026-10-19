"""SARIF output and the migration lookup behind its locations."""

from __future__ import annotations

import json
import shutil

from conftest import EXAMPLE_DIR
from factories import supabase_project
from test_integration import EXPECTED

from se_check.audit import AuditReport
from se_check.cli import main
from se_check.locate import find_definition, sql_sources
from se_check.models import Finding, Severity
from se_check.rules import ALL_RULES
from se_check.sarif import fingerprint, to_sarif


def _finding(check="rls-disabled", obj="public.invoices", severity=Severity.CRITICAL, **evidence):
    return Finding(check, severity, obj, "Title", "Detail.", "Fix it.", dict(evidence))


def _report(*findings: Finding) -> AuditReport:
    return AuditReport("16.2", ("public",), ("anon", "authenticated"), (), tuple(findings))


def _project_with_migrations(root, *migrations: str):
    project = supabase_project(root)
    folder = project / "supabase" / "migrations"
    folder.mkdir()
    for number, sql in enumerate(migrations, start=1):
        (folder / f"2026010100000{number}_m.sql").write_text(sql)
    return project


# --- finding the defining migration -----------------------------------------------------------


def test_table_policy_and_function_definitions_are_found(tmp_path):
    project = _project_with_migrations(
        tmp_path,
        "-- first\ncreate table invoices (id int);\n",
        "\n\nCREATE TABLE IF NOT EXISTS public.invoices_archive (id int);\n"
        'create policy "read all" on public.plans for select using (true);\n'
        "create or replace function public.delete_tenant(p uuid) returns void as $$ $$;\n",
    )
    sources = sql_sources(project)

    table = find_definition(_finding(), sources)
    assert (table.path.name, table.line) == ("20260101000001_m.sql", 2)

    policy = _finding("permissive-policy", "public.plans", policy="read all")
    assert find_definition(policy, sources).line == 4

    function = _finding("definer-no-caller-check", "public.delete_tenant(p uuid)")
    assert find_definition(function, sources).line == 5

    # invoices_archive is not invoices, and unknown objects have no location
    assert find_definition(_finding(obj="public.archive"), sources) is None


def test_the_latest_definition_wins(tmp_path):
    project = _project_with_migrations(
        tmp_path,
        "create function public.f() returns int as 'select 1' language sql;\n",
        "\ncreate or replace function f() returns int as 'select 2' language sql;\n",
    )
    found = find_definition(_finding(obj="public.f()"), sql_sources(project))
    assert (found.path.name, found.line) == ("20260101000002_m.sql", 2)


def test_other_schemas_do_not_match(tmp_path):
    project = _project_with_migrations(tmp_path, "create table private.invoices (id int);\n")
    assert find_definition(_finding(), sql_sources(project)) is None


# --- SARIF document ---------------------------------------------------------------------------


def test_sarif_document(tmp_path):
    project = _project_with_migrations(
        tmp_path / "repo" / "apps" / "db", "create table invoices();\n"
    )
    (tmp_path / "repo" / ".git").mkdir()  # the repository root is two levels up
    unknown = _finding("permissive-policy", "public.plans", Severity.LOW, policy="p")
    sarif = to_sarif(_report(_finding(), unknown), project=project)

    assert sarif["version"] == "2.1.0"
    run = sarif["runs"][0]
    rules = {rule["id"]: rule for rule in run["tool"]["driver"]["rules"]}
    assert set(rules) == {rule.id for rule in ALL_RULES}  # probe rules too
    assert rules["rls-disabled"]["properties"]["security-severity"] == "9.5"
    assert rules["probe-anon-access"]["properties"]["security-severity"] == "9.5"

    found, fallback = run["results"]
    assert found["level"] == "error"
    location = found["locations"][0]["physicalLocation"]
    assert location["artifactLocation"]["uri"] == "apps/db/supabase/migrations/20260101000001_m.sql"
    assert location["region"]["startLine"] == 1
    assert fallback["level"] == "note"
    assert (
        fallback["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
        == "apps/db/supabase/config.toml"
    )


def test_without_a_project_results_have_no_location():
    [result] = to_sarif(_report(_finding()))["runs"][0]["results"]
    assert "locations" not in result


def test_fingerprints_are_stable_and_tell_policies_apart():
    a = _finding("permissive-policy", "public.plans", policy="a")
    assert fingerprint(a) == fingerprint(_finding("permissive-policy", "public.plans", policy="a"))
    assert fingerprint(a) != fingerprint(_finding("permissive-policy", "public.plans", policy="b"))


def test_cli_writes_sarif_next_to_the_text_report(example_dsn, tmp_path, capsys):
    project = supabase_project(tmp_path / "app")
    migrations = project / "supabase" / "migrations"
    migrations.mkdir()
    for path in sorted(EXAMPLE_DIR.glob("*.sql")):
        shutil.copy(path, migrations / path.name)
    output = tmp_path / "se-check.sarif"

    args = ["audit", "--dsn", example_dsn, "--project", str(project), "--sarif", str(output)]
    assert main([*args, "--no-color"]) == 1
    assert "findings:" in capsys.readouterr().out  # the text report still goes to the log

    results = json.loads(output.read_text())["runs"][0]["results"]
    assert len(results) == len(EXPECTED)
    invoices = next(r for r in results if r["properties"]["object"] == "public.invoices")
    uri = invoices["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
    assert uri.endswith("supabase/migrations/10_acme_notes.sql")

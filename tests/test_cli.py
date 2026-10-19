from __future__ import annotations

import io
import json

import pytest
from factories import POOLER_URL, supabase_project
from psycopg.conninfo import conninfo_to_dict
from test_integration import EXPECTED, EXPECTED_PROBE

from se_check import cli
from se_check.audit import AuditReport
from se_check.cli import DSN_ENV, PASSWORD_ENV, build_parser, main, resolve_target
from se_check.probe.model import ProbeCoverage


@pytest.fixture(autouse=True)
def clean_environment(monkeypatch, tmp_path):
    """No inherited configuration, no keyboard, and a folder outside any Supabase project."""
    monkeypatch.delenv(DSN_ENV, raising=False)
    monkeypatch.delenv(PASSWORD_ENV, raising=False)
    monkeypatch.setattr("sys.stdin", io.StringIO(""))
    monkeypatch.chdir(tmp_path)


def _resolve(*argv: str, interactive: bool = False):
    return resolve_target(build_parser().parse_args(["audit", *argv]), interactive=interactive)


def _fake_password(monkeypatch, password: str = "s3cret") -> None:
    monkeypatch.setattr(cli.getpass, "getpass", lambda prompt: password)


# --- running an audit -------------------------------------------------------------------------


def test_audit_json_and_exit_code(example_dsn, capsys):
    code = main(["audit", "--dsn", example_dsn, "--format", "json"])
    captured = capsys.readouterr()
    report = json.loads(captured.out)  # stdout holds nothing but the report
    assert code == 1  # there are critical and high findings
    assert report["summary"]["critical"] == 1
    assert len(report["findings"]) == len(EXPECTED)
    assert "Auditing the database given with --dsn" in captured.err


def test_audit_reads_dsn_from_environment(example_dsn, capsys, monkeypatch):
    monkeypatch.setenv(DSN_ENV, example_dsn)
    code = main(["audit", "--check", "rls-disabled", "--fail-on", "never", "--no-color"])
    out = capsys.readouterr().out
    assert code == 0
    assert "CRITICAL  public.invoices  [rls-disabled]" in out
    assert "permissive-policy" not in out
    assert "2 findings: 1 critical, 1 low" in out


def test_min_severity_hides_but_does_not_change_exit_code(example_dsn, capsys):
    args = ["--format", "json", "--min-severity", "critical"]
    code = main(["audit", "--dsn", example_dsn, *args])
    report = json.loads(capsys.readouterr().out)
    assert code == 1
    assert {f["severity"] for f in report["findings"]} == {"critical"}
    assert report["hidden_below_min_severity"] == len(EXPECTED) - 1  # all but the critical one


def test_unknown_check_is_rejected_by_argparse(capsys):
    with pytest.raises(SystemExit) as exc:
        main(["audit", "--check", "nope"])
    assert exc.value.code == 2


def test_checks_lists_every_check(capsys):
    assert main(["checks"]) == 0
    out = capsys.readouterr().out
    for check_id in ("rls-disabled", "permissive-policy", "user-metadata-auth"):
        assert check_id in out
    assert "Dynamic probe (se-check audit --probe):" in out
    assert "probe-cross-tenant-write" in out


# --- the dynamic probe ------------------------------------------------------------------------


def test_probe_adds_its_findings_and_coverage(example_dsn, capsys):
    code = main(["audit", "--dsn", example_dsn, "--probe", "--format", "json"])
    captured = capsys.readouterr()
    report = json.loads(captured.out)
    assert code == 1
    assert len(report["findings"]) == len(EXPECTED) + len(EXPECTED_PROBE)
    assert report["probe"]["complete"] is True
    assert report["probe"]["tables"] == {"reached": 12, "of": 12}
    assert "rolled back" in captured.err


def test_probe_rules_can_be_selected(example_dsn, capsys):
    args = ["--probe", "--check", "probe-anon-access", "--fail-on", "never", "--no-color"]
    assert main(["audit", "--dsn", example_dsn, *args]) == 0
    out = capsys.readouterr().out
    assert "CRITICAL  public.invoices  [probe-anon-access]" in out
    assert "[rls-disabled]" not in out
    assert "Probe: " in out


@pytest.mark.parametrize(
    ("argv", "message"),
    [
        (["--check", "probe-anon-access"], "come(s) from the dynamic probe: add --probe"),
        (["--probe-remote"], "only makes sense together with --probe"),
        (["--min-coverage", "80"], "--min-coverage only makes sense together with --probe"),
        (["--probe", "--dsn", "postgresql://u:pw@db.example.com/db"], "add --probe-remote"),
    ],
)
def test_probe_misuse_is_a_usage_error(argv, message, capsys):
    assert main(["audit", *argv]) == 2
    err = capsys.readouterr().err
    assert message in err
    assert "Auditing" not in err  # refused before connecting


def test_min_coverage_must_be_a_percentage(capsys):
    with pytest.raises(SystemExit):
        main(["audit", "--probe", "--min-coverage", "120"])
    assert "expected a percentage from 0 to 100, got '120'" in capsys.readouterr().err


def _probe_coverage(reached: int, of: int, *, blocked: str | None = None):
    targets = tuple(f"public.t{i}" for i in range(of))
    return ProbeCoverage("t", (), targets[:reached], (), (), 0, blocked=blocked, targets=targets)


@pytest.mark.parametrize(
    ("coverage", "min_coverage", "code", "message"),
    [
        (_probe_coverage(9, 10), "90", 0, ""),
        (
            _probe_coverage(3, 10),
            "80",
            1,
            "the probe reached 3 of 10 tables (30%), less than --min-coverage 80%",
        ),
        (
            _probe_coverage(0, 10, blocked="no SET ROLE"),
            "1",
            1,
            "the probe did not run (0%), less than --min-coverage 1%",
        ),
    ],
)
def test_min_coverage_fails_the_run(monkeypatch, capsys, coverage, min_coverage, code, message):
    report = AuditReport("16.2", ("public",), (), (), (), probe=coverage)
    monkeypatch.setattr(cli, "run_audit", lambda *args, **kwargs: report)
    argv = ["audit", "--dsn", "postgresql://u:pw@localhost/db", "--probe", "--no-color"]
    assert main([*argv, "--min-coverage", min_coverage]) == code
    assert message in capsys.readouterr().err


def test_linked_probe_is_refused_before_asking_for_the_password(tmp_path, monkeypatch, capsys):
    supabase_project(tmp_path, pooler_url=POOLER_URL)
    asked = []
    monkeypatch.setattr(cli.getpass, "getpass", lambda prompt: asked.append(prompt) or "pw")
    assert main(["audit", "--project", str(tmp_path), "--linked", "--probe"]) == 2
    assert "The linked project is not on this machine" in capsys.readouterr().err
    assert asked == []


def test_settings_feed_the_probe_configuration(tmp_path):
    (tmp_path / "se-check.toml").write_text('[probe]\nskip_tables = ["public.events"]\n')
    plan = cli.build_plan(build_parser().parse_args(["audit"]))
    assert plan.probe.skip_tables == ("public.events",)


# --- which database: a Supabase project folder ------------------------------------------------


def test_project_folder_means_its_local_database(tmp_path, monkeypatch):
    project = supabase_project(tmp_path / "app", "[db]\nport = 55432\n")
    monkeypatch.chdir(project)
    target = _resolve()
    assert target.dsn == "postgresql://postgres:postgres@127.0.0.1:55432/postgres"
    assert "app" in target.label


def test_project_option_points_at_another_folder(tmp_path):
    project = supabase_project(tmp_path / "app")
    assert "127.0.0.1:54322" in _resolve("--project", str(project)).dsn


def test_local_database_not_running_gives_a_hint(tmp_path, capsys):
    project = supabase_project(tmp_path / "app", "[db]\nport = 1\n")  # nothing listens there
    assert main(["audit", "--project", str(project)]) == 2
    err = capsys.readouterr().err
    assert "hint:" in err
    assert "supabase start" in err


def test_linked_uses_the_saved_url_and_asks_for_the_password(tmp_path, monkeypatch):
    project = supabase_project(tmp_path / "app", pooler_url=POOLER_URL)
    _fake_password(monkeypatch, "pa ss@word")
    target = _resolve("--linked", "--project", str(project), interactive=True)
    params = conninfo_to_dict(target.dsn)
    assert params["host"] == "aws-0-eu-west-1.pooler.supabase.com"
    assert params["password"] == "pa ss@word"


def test_linked_reads_the_password_from_the_supabase_variable(tmp_path, monkeypatch):
    project = supabase_project(tmp_path / "app", pooler_url=POOLER_URL)
    monkeypatch.setenv(PASSWORD_ENV, "from-env")
    target = _resolve("--linked", "--project", str(project))
    assert conninfo_to_dict(target.dsn)["password"] == "from-env"


def test_linked_without_keyboard_or_variable_explains_what_to_set(tmp_path):
    project = supabase_project(tmp_path / "app", pooler_url=POOLER_URL)
    with pytest.raises(cli._UsageError, match=PASSWORD_ENV):
        _resolve("--linked", "--project", str(project))


def test_linked_before_supabase_link_says_so(tmp_path, capsys):
    project = supabase_project(tmp_path / "app")
    assert main(["audit", "--linked", "--project", str(project)]) == 2
    assert "supabase link" in capsys.readouterr().err


def test_linked_outside_a_project_says_so(capsys):
    assert main(["audit", "--linked"]) == 2
    assert "supabase/config.toml" in capsys.readouterr().err


# --- which database: explicit connection strings ----------------------------------------------


def test_environment_beats_the_local_project(tmp_path, monkeypatch):
    monkeypatch.chdir(supabase_project(tmp_path / "app"))
    monkeypatch.setenv(DSN_ENV, "postgresql://u:pw@elsewhere/db")
    assert _resolve().dsn == "postgresql://u:pw@elsewhere/db"


def test_dsn_option_beats_the_environment(monkeypatch):
    monkeypatch.setenv(DSN_ENV, "postgresql://u:pw@elsewhere/db")
    assert _resolve("--dsn", "postgresql://u:pw@here/db").dsn == "postgresql://u:pw@here/db"


def test_dashboard_placeholder_asks_for_the_password(monkeypatch):
    _fake_password(monkeypatch)
    dsn = "postgresql://postgres:[YOUR-PASSWORD]@db.abcdefgh.supabase.co:5432/postgres"
    target = _resolve("--dsn", dsn, interactive=True)
    assert conninfo_to_dict(target.dsn)["password"] == "s3cret"
    assert "IPv6" in target.hint


def test_nothing_configured_and_no_keyboard_is_a_usage_error(capsys):
    assert main(["audit"]) == 2
    err = capsys.readouterr().err
    assert "Supabase project folder" in err
    assert "--dsn" in err


def test_nothing_configured_asks_to_paste_a_connection_string(monkeypatch, capsys):
    monkeypatch.setattr("sys.stdin", io.StringIO(POOLER_URL + "\n"))
    _fake_password(monkeypatch)
    target = _resolve(interactive=True)
    params = conninfo_to_dict(target.dsn)
    assert params["user"] == "postgres.abcdefgh"
    assert params["password"] == "s3cret"
    assert "Paste a connection string" in capsys.readouterr().err


def test_pasting_nothing_cancels():
    with pytest.raises(cli._UsageError, match="no database"):
        _resolve(interactive=True)


# --- se-check.toml ----------------------------------------------------------------------------


def test_accept_writes_next_to_the_supabase_folder(tmp_path, monkeypatch, capsys):
    project = supabase_project(tmp_path / "app")
    monkeypatch.chdir(project / "supabase")  # from a subfolder too
    args = ["accept", "permissive-policy", "public.plans", "--reason", "Public pricing."]
    assert main(args) == 0
    assert main(args) == 0  # same entry twice: no duplicate
    out = capsys.readouterr().out
    assert "already accepted" in out
    text = (project / "se-check.toml").read_text()
    assert text.splitlines().count("[[accept]]") == 1
    assert 'reason = "Public pricing."' in text


def test_accept_needs_a_real_reason(tmp_path, capsys):
    assert main(["accept", "rls-disabled", "public.t", "--reason", "   "]) == 2
    assert "reason" in capsys.readouterr().err
    assert not (tmp_path / "se-check.toml").exists()


def test_accepted_findings_leave_the_report_and_stop_failing(example_dsn, tmp_path, capsys):
    config = tmp_path / "se-check.toml"
    accept = ["accept", "rls-disabled", "public.invoices", "--config", str(config)]
    main([*accept, "--reason", "Demo table, filled with fake data."])
    capsys.readouterr()

    audit = ["audit", "--dsn", example_dsn, "--config", str(config), "--check", "rls-disabled"]
    assert main([*audit, "--fail-on", "critical", "--format", "json"]) == 0
    report = json.loads(capsys.readouterr().out)
    assert [f["object"] for f in report["findings"]] == ["public.audit_log"]
    assert report["accepted"][0]["object"] == "public.invoices"
    assert report["accepted"][0]["reason"] == "Demo table, filled with fake data."

    main([*audit, "--no-color"])
    assert "Accepted in se-check.toml (1):" in capsys.readouterr().out


def test_stale_acceptances_are_reported(example_dsn, tmp_path, capsys):
    config = tmp_path / "se-check.toml"
    main(["accept", "rls-disabled", "public.dropped", "--reason", "x", "--config", str(config)])
    capsys.readouterr()
    main(["audit", "--dsn", example_dsn, "--config", str(config), "--no-color"])
    out = capsys.readouterr().out
    assert "no longer occur" in out
    assert "rls-disabled public.dropped" in out


def test_broken_settings_stop_the_audit_with_a_clear_message(tmp_path, capsys):
    (tmp_path / "se-check.toml").write_text('[[accept]]\ncheck = "rls-disabled"\nobject = "t"\n')
    assert main(["audit", "--dsn", "postgresql://u:pw@nowhere/db"]) == 2
    assert "has no reason" in capsys.readouterr().err


def test_settings_feed_the_audit_configuration(tmp_path):
    (tmp_path / "se-check.toml").write_text(
        'schemas = ["api"]\ntenant_columns = ["clinic_id"]\nguards = ["is_staff"]\n'
    )
    plan = cli.build_plan(build_parser().parse_args(["audit", "--guard", "extra"]))
    assert plan.config.schemas == ("api",)
    assert "clinic_id" in plan.config.tenant_columns
    assert "tenant_id" in plan.config.tenant_columns  # built-ins stay
    assert plan.config.guard_functions == ("is_staff", "extra")
    # the command line wins over the file
    plan = cli.build_plan(build_parser().parse_args(["audit", "--schema", "public"]))
    assert plan.config.schemas == ("public",)


def test_mcp_probe_refuses_databases_elsewhere(capsys):
    argv = ["mcp", "--probe", "--dsn", "postgresql://u:pw@db.example.com/db"]
    assert main(argv) == 2
    assert "se-check mcp --probe only runs on a local database" in capsys.readouterr().err


def test_mcp_probe_refuses_the_linked_project(tmp_path, capsys):
    supabase_project(tmp_path, pooler_url=POOLER_URL)
    assert main(["mcp", "--project", str(tmp_path), "--linked", "--probe"]) == 2
    assert "The linked project is not on this machine" in capsys.readouterr().err

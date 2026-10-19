"""Working out which database to audit."""

from __future__ import annotations

import pytest
from factories import POOLER_URL, supabase_project
from psycopg.conninfo import conninfo_to_dict

from se_check.connection import (
    LOCAL_DB_PORT,
    TargetError,
    access_token_hook,
    auth_hooks,
    dsn_target,
    find_supabase_project,
    has_password,
    has_placeholder,
    is_local,
    linked_target,
    local_target,
    with_password,
)

DASHBOARD_DSN = "postgresql://postgres:[YOUR-PASSWORD]@db.abcdefgh.supabase.co:5432/postgres"
NASTY_PASSWORD = "p@ss:w/rd#?'\" x%"


def test_project_is_found_from_a_subfolder(tmp_path):
    project = supabase_project(tmp_path / "app")
    subfolder = project / "src" / "components"
    subfolder.mkdir(parents=True)
    assert find_supabase_project(subfolder) == project.resolve()


def test_no_project(tmp_path):
    assert find_supabase_project(tmp_path) is None


def test_local_target_reads_the_port_from_config(tmp_path):
    target = local_target(supabase_project(tmp_path, "[db]\nport = 55432\nmajor_version = 17\n"))
    assert target.dsn == "postgresql://postgres:postgres@127.0.0.1:55432/postgres"
    assert "supabase start" in target.hint


@pytest.mark.parametrize("config", ["", "[api]\nport = 1\n", "[db]\nport = 'x'\n", "not [[ toml"])
def test_local_target_falls_back_to_the_default_port(tmp_path, config):
    assert f":{LOCAL_DB_PORT}/" in local_target(supabase_project(tmp_path, config)).dsn


def test_auth_hooks_are_read_from_config(tmp_path):
    project = supabase_project(
        tmp_path,
        "[auth.hook.custom_access_token]\nenabled = true\n"
        'uri = "pg-functions://postgres/public/custom_access_token_hook"\n'
        "[auth.hook.send_email]\nenabled = true\n"
        'uri = "https://example.com/send-email"\n',
    )
    assert auth_hooks(project) == ("public.custom_access_token_hook",)
    assert auth_hooks(supabase_project(tmp_path / "other")) == ()


def test_linked_target_combines_the_saved_url_and_the_password(tmp_path):
    target = linked_target(supabase_project(tmp_path, pooler_url=POOLER_URL), NASTY_PASSWORD)
    params = conninfo_to_dict(target.dsn)
    assert params["password"] == NASTY_PASSWORD  # no URL-encoding needed
    assert params["user"] == "postgres.abcdefgh"
    assert params["host"] == "aws-0-eu-west-1.pooler.supabase.com"


def test_linked_target_needs_supabase_link(tmp_path):
    with pytest.raises(TargetError, match="supabase link"):
        linked_target(supabase_project(tmp_path), "pw")


def test_dashboard_placeholder_is_replaced_by_the_password():
    assert has_placeholder(DASHBOARD_DSN)
    params = conninfo_to_dict(with_password(DASHBOARD_DSN, NASTY_PASSWORD))
    assert params["password"] == NASTY_PASSWORD
    assert params["user"] == "postgres"


def test_has_password():
    assert has_password("postgresql://user:pw@host/db")
    assert not has_password("postgresql://user@host/db")
    assert not has_password("this is not a connection string")


def test_direct_connections_get_the_ipv6_hint():
    assert "IPv6" in dsn_target(DASHBOARD_DSN, "x").hint
    assert dsn_target(with_password(DASHBOARD_DSN, "pw"), "x").hint != ""
    assert dsn_target(POOLER_URL, "x").hint == ""


@pytest.mark.parametrize(
    ("dsn", "local"),
    [
        ("postgresql://postgres:postgres@127.0.0.1:54322/postgres", True),
        ("postgresql://u@localhost/db", True),
        ("postgresql://u@[::1]:5432/db", True),
        ("postgresql:///db", True),  # the default Unix socket
        ("host=/var/run/postgresql dbname=db", True),
        (POOLER_URL, False),
        (DASHBOARD_DSN, False),
        ("postgresql://u@localhost,db.example.com/db", False),  # every host must be local
        ("host=db.example.com hostaddr=127.0.0.1 dbname=db", True),  # hostaddr is what connects
    ],
)
def test_local_targets(dsn, local):
    assert is_local(dsn) is local
    assert dsn_target(dsn, "x").local is local


def test_the_local_stack_is_local_and_linked_projects_are_not(tmp_path):
    project = supabase_project(tmp_path, pooler_url=POOLER_URL)
    assert local_target(project).local
    assert not linked_target(project, "pw").local


def test_access_token_hook_is_read_from_config(tmp_path):
    project = supabase_project(
        tmp_path,
        config="[auth.hook.custom_access_token]\nenabled = true\n"
        'uri = "pg-functions://postgres/public/custom_access_token_hook"\n'
        "[auth.hook.send_email]\n"
        'uri = "pg-functions://postgres/public/send_email"\n',
    )
    assert access_token_hook(project) == "public.custom_access_token_hook"
    assert access_token_hook(supabase_project(tmp_path / "other")) is None

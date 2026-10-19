"""Database fixtures.

Database tests need a Postgres superuser. They use, in order:
  1. the server in $SE_CHECK_TEST_DSN (CI does this), or
  2. a throwaway server started with `pgserver` (installed with the dev dependencies).
Without either, they are skipped. Each session works in a fresh database that is dropped
at the end, so a shared server is left as it was (roles excepted: they are cluster-wide).
"""

from __future__ import annotations

import os
import uuid
from pathlib import Path

import psycopg
import pytest
from psycopg import sql
from psycopg.conninfo import make_conninfo

EXAMPLE_DIR = Path(__file__).resolve().parent.parent / "examples" / "vulnerable-app"


@pytest.fixture(scope="session")
def server_dsn(tmp_path_factory: pytest.TempPathFactory):
    dsn = os.environ.get("SE_CHECK_TEST_DSN")
    if dsn:
        yield dsn
        return
    pgserver = pytest.importorskip(
        "pgserver", reason="set SE_CHECK_TEST_DSN or install pgserver to run database tests"
    )
    server = pgserver.get_server(tmp_path_factory.mktemp("pgdata"), cleanup_mode="stop")
    yield server.get_uri()
    server.cleanup()


SUPABASE_POSTGRES = "se_check_supabase_postgres"
"""A role shaped like Supabase's `postgres` (see supabase/postgres, migrations/db)."""

API_ROLES_SQL = """
do $$
begin
  if not exists (select from pg_roles where rolname = 'anon') then
    create role anon nologin noinherit;
  end if;
  if not exists (select from pg_roles where rolname = 'authenticated') then
    create role authenticated nologin noinherit;
  end if;
  if not exists (select from pg_roles where rolname = 'service_role') then
    create role service_role nologin noinherit bypassrls;
  end if;
  if not exists (select from pg_roles where rolname = 'supabase_auth_admin') then
    create role supabase_auth_admin nologin noinherit;
  end if;
end
$$
"""


def _load_example(dsn: str) -> None:
    with psycopg.connect(dsn, autocommit=True) as conn:
        for path in sorted(EXAMPLE_DIR.glob("*.sql")):
            conn.execute(path.read_text())


def _new_database(server_dsn: str, owner: str | None = None) -> str:
    name = f"se_check_test_{uuid.uuid4().hex[:8]}"
    statement = sql.SQL("create database {}").format(sql.Identifier(name))
    if owner:
        statement += sql.SQL(" owner {}").format(sql.Identifier(owner))
    with psycopg.connect(server_dsn, autocommit=True) as admin:
        admin.execute(statement)
    return name


def _drop_database(server_dsn: str, name: str) -> None:
    with psycopg.connect(server_dsn, autocommit=True) as admin:
        admin.execute(
            sql.SQL("drop database if exists {} with (force)").format(sql.Identifier(name))
        )


@pytest.fixture
def fresh_example(server_dsn: str):
    """Make a new database loaded with the example app, for tests that change it; with
    `stub_only`, just the Supabase stand-in."""
    names: list[str] = []

    def make(*, stub_only: bool = False) -> str:
        names.append(_new_database(server_dsn))
        dsn = make_conninfo(server_dsn, dbname=names[-1])
        if stub_only:
            with psycopg.connect(dsn, autocommit=True) as conn:
                conn.execute((EXAMPLE_DIR / "00_supabase_stub.sql").read_text())
        else:
            _load_example(dsn)
        return dsn

    try:
        yield make
    finally:
        for name in names:
            _drop_database(server_dsn, name)


@pytest.fixture(scope="session")
def supabase_role_dsn(server_dsn: str):
    """The example app owned by, and audited as, a role shaped like Supabase's `postgres`:
    NOSUPERUSER but BYPASSRLS, and a member of the API roles. The other fixtures connect as
    a superuser, which Supabase never hands out."""
    password = uuid.uuid4().hex
    role = sql.Identifier(SUPABASE_POSTGRES)
    with psycopg.connect(server_dsn, autocommit=True) as admin:
        # The superuser makes the API roles, as on Supabase: a role made by a CREATEROLE user
        # is granted back to it without SET (PG16), and SET ROLE would fail.
        admin.execute(API_ROLES_SQL)
        exists = admin.execute(
            "select 1 from pg_roles where rolname = %s", (SUPABASE_POSTGRES,)
        ).fetchone()
        verb = sql.SQL("alter" if exists else "create")
        admin.execute(
            sql.SQL("{} role {} login nosuperuser createrole bypassrls password {}").format(
                verb, role, sql.Literal(password)
            )
        )
    name = _new_database(server_dsn, owner=SUPABASE_POSTGRES)
    try:
        dsn = make_conninfo(server_dsn, dbname=name, user=SUPABASE_POSTGRES, password=password)
        _load_example(dsn)
        with psycopg.connect(server_dsn, autocommit=True) as admin:
            admin.execute(sql.SQL("grant anon, authenticated, service_role to {}").format(role))
        yield dsn
    finally:
        _drop_database(server_dsn, name)


@pytest.fixture(scope="session")
def example_dsn(server_dsn: str):
    """A fresh database loaded with the deliberately vulnerable example app."""
    name = _new_database(server_dsn)
    dsn = make_conninfo(server_dsn, dbname=name)
    try:
        _load_example(dsn)
        with psycopg.connect(dsn, autocommit=True) as conn:
            # Functions owned by an extension are not project code and must be ignored. This
            # one would trip two checks; making it a member of plpgsql (always installed)
            # proves the filter works without depending on contrib packages.
            conn.execute(
                "create function public.extension_owned() returns void "
                "language sql security definer as 'select'"
            )
            conn.execute("alter extension plpgsql add function public.extension_owned()")
        yield dsn
    finally:
        _drop_database(server_dsn, name)

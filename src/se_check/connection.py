"""Work out which database to audit, so the common cases need no setup.

From a Supabase project folder (the one with `supabase/config.toml`), se-check finds the local
database on its own, and `--linked` reaches the hosted project that `supabase link` connected
the folder to: only the database password is missing there. Anything else is a connection
string, given with --dsn / $SE_CHECK_DSN or pasted at the prompt.
"""

from __future__ import annotations

import ipaddress
import re
import sys
from dataclasses import dataclass
from pathlib import Path

import psycopg
from psycopg.conninfo import conninfo_to_dict, make_conninfo

if sys.version_info >= (3, 11):
    import tomllib
else:  # pragma: no cover
    import tomli as tomllib

LOCAL_DB_PORT = 54322
"""Supabase CLI default for `[db] port` in supabase/config.toml."""

PASSWORD_PLACEHOLDER = "[YOUR-PASSWORD]"
"""What the Supabase dashboard puts in the connection strings it lets you copy."""

_DIRECT_HOST = re.compile(r"db\.[a-z0-9]+\.supabase\.co", re.IGNORECASE)


class TargetError(Exception):
    """No usable database could be worked out."""


@dataclass(frozen=True)
class Target:
    dsn: str
    label: str
    """What is being audited, in words."""
    hint: str = ""
    """What to try when connecting fails."""
    local: bool = False
    """On this machine: the local Supabase stack, or a loopback address or Unix socket."""


def find_supabase_project(start: Path) -> Path | None:
    """The closest folder, from `start` upwards, that holds supabase/config.toml."""
    start = start.resolve()
    for folder in (start, *start.parents):
        if (folder / "supabase" / "config.toml").is_file():
            return folder
    return None


def local_target(project: Path) -> Target:
    port = _local_port(project / "supabase" / "config.toml")
    return Target(
        dsn=f"postgresql://postgres:postgres@127.0.0.1:{port}/postgres",
        label=f"the local database of {project.name} (port {port})",
        hint="Is the local stack running? Start it with `supabase start`, or audit the hosted "
        "project with `se-check audit --linked`.",
        local=True,
    )


def _read_config(project: Path) -> dict:
    try:
        return tomllib.loads((project / "supabase" / "config.toml").read_text())
    except (OSError, tomllib.TOMLDecodeError):
        return {}


def _local_port(config_file: Path) -> int:
    port = _read_config(config_file.parent.parent).get("db", {}).get("port")
    return port if isinstance(port, int) else LOCAL_DB_PORT


def auth_hooks(project: Path) -> tuple[str, ...]:
    """`schema.function` of the Postgres functions configured as Auth hooks.

    In supabase/config.toml they look like:
        [auth.hook.custom_access_token]
        uri = "pg-functions://postgres/public/custom_access_token_hook"
    """
    hooks = _read_config(project).get("auth", {}).get("hook", {})
    names = []
    for hook in hooks.values() if isinstance(hooks, dict) else ():
        uri = hook.get("uri", "") if isinstance(hook, dict) else ""
        match = re.fullmatch(r"pg-functions://[^/]+/([^/]+)/([^/]+)", str(uri))
        if match:
            names.append(f"{match.group(1)}.{match.group(2)}")
    return tuple(names)


def access_token_hook(project: Path) -> str | None:
    """`schema.function` of `[auth.hook.custom_access_token]`, if it is a Postgres function."""
    hook = _read_config(project).get("auth", {}).get("hook", {}).get("custom_access_token")
    uri = hook.get("uri", "") if isinstance(hook, dict) else ""
    match = re.fullmatch(r"pg-functions://[^/]+/([^/]+)/([^/]+)", str(uri))
    return f"{match.group(1)}.{match.group(2)}" if match else None


def linked_pooler_url(project: Path) -> str:
    """The connection string, without password, that `supabase link` saved for the project."""
    try:
        url = (project / "supabase" / ".temp" / "pooler-url").read_text().strip()
    except OSError:
        url = ""
    if not url:
        raise TargetError(
            f"{project.name} is not linked to a hosted Supabase project yet: run "
            "`supabase link` in it first, or pass a connection string with --dsn."
        )
    return url


def linked_target(project: Path, password: str) -> Target:
    return Target(
        dsn=with_password(linked_pooler_url(project), password),
        label=f"the hosted Supabase project linked to {project.name}",
        hint="Check the database password: it is the one set for the database (Dashboard → "
        "Project Settings → Database), not the password of your Supabase account.",
    )


def has_placeholder(dsn: str) -> bool:
    return PASSWORD_PLACEHOLDER in dsn


def has_password(dsn: str) -> bool:
    try:
        return bool(conninfo_to_dict(dsn).get("password"))
    except psycopg.Error:
        return False


def with_password(dsn: str, password: str) -> str:
    """Put the password into a connection string. Any character works: no URL-encoding."""
    return make_conninfo(dsn.replace(":" + PASSWORD_PLACEHOLDER, ""), password=password)


def is_local(dsn: str) -> bool:
    """Whether every host of the connection string is a loopback address or a Unix socket.

    No host at all means the default Unix socket.
    """
    try:
        params = conninfo_to_dict(dsn.replace(":" + PASSWORD_PLACEHOLDER, ""))
    except psycopg.Error:
        return False
    hosts = str(params.get("hostaddr") or params.get("host") or "").split(",")
    return all(_is_loopback(host.strip()) for host in hosts)


def _is_loopback(host: str) -> bool:
    if not host or host.startswith("/") or host.lower() == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def dsn_target(dsn: str, label: str) -> Target:
    """A connection string from the user, with a hint for the classic Supabase pitfall."""
    try:
        host = conninfo_to_dict(dsn.replace(":" + PASSWORD_PLACEHOLDER, "")).get("host", "")
    except psycopg.Error:
        host = ""
    hint = ""
    if _DIRECT_HOST.fullmatch(str(host)):
        hint = (
            "This is a direct connection (db.<project>.supabase.co), which needs IPv6: many "
            "networks don't have it. Copy the Session pooler string instead (Dashboard → "
            "Connect), or run `supabase link` in your project and then `se-check audit --linked`."
        )
    return Target(dsn=dsn, label=label, hint=hint, local=is_local(dsn))

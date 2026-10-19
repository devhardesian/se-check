"""se-check.toml: project settings, and the findings the team has reviewed and accepted.

    # se-check.toml, next to the supabase/ folder
    tenant_columns = ["clinic_id"]

    [[accept]]
    check = "permissive-policy"
    object = "public.plans"
    policy = "plans are public"   # optional: only this policy of the table
    reason = "Pricing plans are shown on the public landing page."

Every accepted finding needs a reason: the file doubles as the record of why each exception
is fine. Accepted findings leave the report and stop failing CI; entries that no longer match
anything are reported, so the file doesn't rot.
"""

from __future__ import annotations

import json
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from se_check.config import ProbeConfig
from se_check.models import Finding

if sys.version_info >= (3, 11):
    import tomllib
else:  # pragma: no cover
    import tomli as tomllib

SETTINGS_FILE = "se-check.toml"

_LIST_SETTINGS = ("schemas", "api_roles", "tenant_columns", "guards")
_ACCEPT_KEYS = ("check", "object", "policy", "reason")
_PROBE_KEYS = ("skip_tables", "values", "claims", "membership", "privilege_columns")

_NEW_FILE_HEADER = """\
# se-check settings and accepted findings.
# Each [[accept]] entry is a finding reviewed on purpose; `reason` records why it is fine.
"""


class SettingsError(Exception):
    """se-check.toml is missing pieces or has a mistake."""


@dataclass(frozen=True)
class Acceptance:
    check: str
    object: str
    reason: str
    policy: str | None = None

    def matches(self, finding: Finding) -> bool:
        if finding.check != self.check or finding.object != self.object:
            return False
        return self.policy is None or finding.evidence.get("policy") == self.policy

    def describe(self) -> str:
        policy = f' (policy "{self.policy}")' if self.policy else ""
        return f"{self.check} {self.object}{policy}"


@dataclass(frozen=True)
class ProjectSettings:
    path: Path | None = None
    schemas: tuple[str, ...] | None = None
    api_roles: tuple[str, ...] | None = None
    tenant_columns: tuple[str, ...] = ()
    guards: tuple[str, ...] = ()
    accepted: tuple[Acceptance, ...] = ()
    probe: ProbeConfig = field(default_factory=ProbeConfig)


def load_settings(path: Path, known_checks: set[str]) -> ProjectSettings:
    try:
        data = tomllib.loads(path.read_text())
    except OSError as exc:
        raise SettingsError(f"cannot read {path}: {exc.strerror}") from exc
    except tomllib.TOMLDecodeError as exc:
        raise SettingsError(f"{path} is not valid TOML: {exc}") from exc

    unknown = sorted(set(data) - {*_LIST_SETTINGS, "accept", "probe"})
    if unknown:
        raise SettingsError(
            f"{path}: unknown setting {', '.join(unknown)} "
            f"(known: {', '.join(_LIST_SETTINGS)}, [probe], [[accept]])"
        )

    lists: dict[str, tuple[str, ...]] = {}
    for key in _LIST_SETTINGS:
        if key not in data:
            continue
        value = data[key]
        if not isinstance(value, list) or not all(isinstance(v, str) and v for v in value):
            raise SettingsError(f'{path}: {key} must be a list of names, e.g. {key} = ["..."]')
        lists[key] = tuple(value)

    entries = data.get("accept", [])
    if not isinstance(entries, list):
        raise SettingsError(f"{path}: write accepted findings as [[accept]] tables")
    accepted = tuple(
        _acceptance(entry, f"{path}: [[accept]] #{number}", known_checks)
        for number, entry in enumerate(entries, start=1)
    )

    return ProjectSettings(
        path=path,
        schemas=lists.get("schemas"),
        api_roles=lists.get("api_roles"),
        tenant_columns=lists.get("tenant_columns", ()),
        guards=lists.get("guards", ()),
        accepted=accepted,
        probe=_probe_settings(data.get("probe", {}), f"{path}: [probe]"),
    )


def _probe_settings(data: object, where: str) -> ProbeConfig:
    if not isinstance(data, dict):
        raise SettingsError(f"{where} must be a table")
    extra = sorted(set(data) - set(_PROBE_KEYS))
    if extra:
        raise SettingsError(
            f"{where}: unknown key {', '.join(extra)} (known: {', '.join(_PROBE_KEYS)})"
        )

    skip_tables = data.get("skip_tables", [])
    if not isinstance(skip_tables, list) or not all(_is_table_name(t) for t in skip_tables):
        raise SettingsError(f'{where}: skip_tables must list tables as "schema.table"')

    values = data.get("values", {})
    if not isinstance(values, dict):
        raise SettingsError(f'{where}: write values as [probe.values."schema.table"] tables')
    table_values: dict[str, dict[str, str]] = {}
    for table, columns in values.items():
        if not _is_table_name(table) or not isinstance(columns, dict):
            raise SettingsError(f'{where}: write values as [probe.values."schema.table"] tables')
        table_values[table] = {}
        for column, value in columns.items():
            if isinstance(value, bool):
                value = "true" if value else "false"
            elif isinstance(value, (int, float)):
                value = str(value)
            if not isinstance(value, str):
                raise SettingsError(
                    f"{where}: values.{table}.{column} must be a string, a number or a boolean"
                )
            table_values[table][column] = value

    claims = data.get("claims", {})
    if not isinstance(claims, dict) or not _is_json(claims):
        raise SettingsError(f"{where}: claims must be a table of JSON-like values")

    privilege_columns = data.get("privilege_columns", [])
    if not isinstance(privilege_columns, list) or not all(
        isinstance(c, str) and c for c in privilege_columns
    ):
        raise SettingsError(
            f'{where}: privilege_columns must list column names, e.g. ["clearance"]'
        )

    membership = data.get("membership")
    if membership is not None and (not isinstance(membership, str) or not membership.strip()):
        raise SettingsError(f"{where}: membership must be an SQL statement")

    return ProbeConfig(
        skip_tables=tuple(skip_tables),
        values=table_values,
        claims=claims,
        membership=membership,
        privilege_columns=tuple(privilege_columns),
    )


def _is_table_name(value: object) -> bool:
    return isinstance(value, str) and "." in value.strip(".")


def _is_json(value: Any) -> bool:
    if isinstance(value, dict):
        return all(isinstance(k, str) and _is_json(v) for k, v in value.items())
    if isinstance(value, list):
        return all(_is_json(v) for v in value)
    return isinstance(value, (str, int, float, bool))


def _acceptance(entry: object, where: str, known_checks: set[str]) -> Acceptance:
    if not isinstance(entry, dict):
        raise SettingsError(f"{where} must be a table")
    extra = sorted(set(entry) - set(_ACCEPT_KEYS))
    if extra:
        raise SettingsError(f"{where}: unknown key {', '.join(extra)}")
    for key in ("check", "object", "policy", "reason"):
        if key in entry and not isinstance(entry[key], str):
            raise SettingsError(f"{where}: {key} must be a string")
    for key in ("check", "object"):
        if not entry.get(key, "").strip():
            raise SettingsError(f'{where} is missing {key} = "..."')
    if entry["check"] not in known_checks:
        raise SettingsError(f"{where}: unknown check {entry['check']!r} (see `se-check checks`)")
    if not entry.get("reason", "").strip():
        raise SettingsError(
            f"{where} ({entry['check']} {entry['object']}) has no reason: write down why this "
            "finding is acceptable"
        )
    return Acceptance(
        check=entry["check"],
        object=entry["object"],
        reason=entry["reason"].strip(),
        policy=entry.get("policy") or None,
    )


def append_acceptance(path: Path, acceptance: Acceptance) -> None:
    """Add an [[accept]] entry at the end of the file, creating the file if needed."""
    lines = [
        "",
        "[[accept]]",
        f"check = {_toml_string(acceptance.check)}",
        f"object = {_toml_string(acceptance.object)}",
    ]
    if acceptance.policy:
        lines.append(f"policy = {_toml_string(acceptance.policy)}")
    lines.append(f"reason = {_toml_string(acceptance.reason)}")
    existing = path.read_text() if path.exists() else _NEW_FILE_HEADER
    path.write_text(existing.rstrip("\n") + "\n" + "\n".join(lines) + "\n")


def _toml_string(value: str) -> str:
    # A JSON string is a valid TOML basic string, except that TOML also forbids a raw DEL.
    return json.dumps(value, ensure_ascii=False).replace("\x7f", "\\u007F")

"""Shared pieces for the checks."""

from __future__ import annotations

import re
from collections.abc import Callable, Iterable
from dataclasses import dataclass

from se_check.catalog import PRIVILEGES, Catalog
from se_check.config import AuditConfig
from se_check.models import Finding, Severity


@dataclass(frozen=True, kw_only=True)
class Rule:
    """Something se-check reports on: a static check, or a scenario of the dynamic probe."""

    id: str
    title: str
    description: str
    max_severity: Severity = Severity.HIGH
    """The most severe finding it can report (code scanning shows it per rule)."""


@dataclass(frozen=True, kw_only=True)
class Check(Rule):
    """A rule decided from the catalog alone."""

    run: Callable[[Catalog, AuditConfig], Iterable[Finding]]


_PLAIN_IDENTIFIER = re.compile(r"[a-z_][a-z0-9_$]*")
_SQL_COMMENT = re.compile(r"--[^\n]*|/\*.*?\*/", re.DOTALL)


def quote_ident(name: str) -> str:
    """Quote an identifier for the SQL we suggest, only when it needs it."""
    if _PLAIN_IDENTIFIER.fullmatch(name):
        return name
    return '"' + name.replace('"', '""') + '"'


def qualified(schema: str, name: str) -> str:
    return f"{quote_ident(schema)}.{quote_ident(name)}"


def strip_sql_comments(sql: str) -> str:
    """Drop comments so that `-- TODO: check auth.uid()` doesn't count as a check."""
    return _SQL_COMMENT.sub(" ", sql)


def calls(function_name: str, sql: str) -> bool:
    """Whether `sql` calls `function_name`, qualified or not."""
    return re.search(rf"\b{re.escape(function_name)}\s*\(", sql, re.IGNORECASE) is not None


def format_privileges(privileges: Iterable[str]) -> str:
    return ", ".join(p for p in PRIVILEGES if p in set(privileges))


def truncate(text: str | None, limit: int = 300) -> str:
    if text is None:
        return ""
    return text if len(text) <= limit else text[: limit - 1] + "…"

"""Point findings at the SQL file that defines the object, so code scanning can annotate it.

Database objects have no file of their own, but in a Supabase project they come from
supabase/migrations (or declarative supabase/schemas). The latest migration that creates the
object is where a reviewer should look, and where the fix usually belongs next to.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

from se_check.models import Finding


@dataclass(frozen=True)
class SourceLocation:
    path: Path
    line: int


def sql_sources(project: Path) -> list[Path]:
    """Migrations in apply order, then declarative schema files."""
    supabase = project / "supabase"
    migrations = sorted((supabase / "migrations").glob("*.sql"))
    schemas = sorted((supabase / "schemas").rglob("*.sql"))
    return migrations + schemas


def _name(name: str) -> str:
    """Regex for an identifier written bare or double-quoted."""
    escaped = re.escape(name)
    return f'(?:"{escaped}"|{escaped}\\b)'


def _qualified(schema: str, name: str) -> str:
    """Regex for `schema.name`, `name` alone (default search_path), quoted or not."""
    return f"(?:{_name(schema)}\\s*\\.\\s*)?{_name(name)}"


def definition_pattern(finding: Finding) -> re.Pattern[str] | None:
    schema, _, rest = finding.object.partition(".")
    if not rest:
        return None
    policy = finding.evidence.get("policy")
    if policy:  # policy findings name the table; the policy is the precise spot
        table = rest
        pattern = (
            rf"create\s+policy\s+{_name(policy)}\s+on\s+(?:only\s+)?{_qualified(schema, table)}"
        )
    elif "(" in rest:
        function = rest.split("(", 1)[0]
        pattern = rf"create\s+(?:or\s+replace\s+)?function\s+{_qualified(schema, function)}\s*\("
    else:
        pattern = (
            rf"create\s+(?:unlogged\s+)?table\s+(?:if\s+not\s+exists\s+)?"
            rf"{_qualified(schema, rest)}"
        )
    return re.compile(pattern, re.IGNORECASE)


def find_definition(finding: Finding, sources: list[Path]) -> SourceLocation | None:
    """The last place, in apply order, where the finding's object is created."""
    pattern = definition_pattern(finding)
    if pattern is None:
        return None
    found: SourceLocation | None = None
    for path in sources:
        try:
            text = path.read_text(errors="replace")
        except OSError:
            continue
        for match in pattern.finditer(text):
            found = SourceLocation(path, text.count("\n", 0, match.start()) + 1)
    return found


def find_repository_root(start: Path) -> Path | None:
    start = start.resolve()
    for folder in (start, *start.parents):
        if (folder / ".git").exists():
            return folder
    return None

"""SARIF 2.1.0 output, for GitHub code scanning and other tools that read it.

Each finding becomes a result pointing at the migration that creates the object, so pull
requests get the annotation on the right line. Accepted findings are left out.
"""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any

from se_check import __version__
from se_check.audit import AuditReport
from se_check.checks.base import Rule
from se_check.locate import SourceLocation, find_definition, find_repository_root, sql_sources
from se_check.models import Finding, Severity
from se_check.rules import ALL_RULES

SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
INFORMATION_URI = "https://github.com/devhardesian/se-check"

_LEVELS = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
    Severity.INFO: "note",
}
# GitHub's scale: 9.0+ critical, 7.0+ high, 4.0+ medium, below that low.
_SECURITY_SEVERITY = {
    Severity.CRITICAL: "9.5",
    Severity.HIGH: "8.0",
    Severity.MEDIUM: "5.5",
    Severity.LOW: "3.0",
    Severity.INFO: "1.0",
}


def fingerprint(finding: Finding) -> str:
    """Stable across runs, so code scanning tracks one alert per problem."""
    key = "|".join((finding.check, finding.object, finding.evidence.get("policy", "")))
    return hashlib.sha256(key.encode()).hexdigest()[:32]


def to_sarif(report: AuditReport, *, project: Path | None = None) -> dict[str, Any]:
    """`project` is the Supabase project folder; without it results carry no file location."""
    sources: list[Path] = []
    root: Path | None = None
    fallback: SourceLocation | None = None
    if project is not None:
        sources = sql_sources(project)
        root = find_repository_root(project) or project.resolve()
        # Code scanning wants a file for every result: when no migration creates the object,
        # point at the project configuration.
        fallback = SourceLocation(project / "supabase" / "config.toml", 1)
    return {
        "$schema": SARIF_SCHEMA,
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "se-check",
                        "version": __version__,
                        "informationUri": INFORMATION_URI,
                        "rules": [_rule(rule) for rule in ALL_RULES],
                    }
                },
                "results": [_result(f, sources, root, fallback) for f in report.findings],
            }
        ],
    }


def _rule(rule: Rule) -> dict[str, Any]:
    return {
        "id": rule.id,
        "name": rule.title,
        "shortDescription": {"text": rule.title},
        "fullDescription": {"text": rule.description},
        "help": {"text": rule.description},
        "defaultConfiguration": {"level": _LEVELS[rule.max_severity]},
        "properties": {
            "tags": ["security", "supabase", "postgres"],
            "security-severity": _SECURITY_SEVERITY[rule.max_severity],
        },
    }


def _result(
    finding: Finding,
    sources: list[Path],
    root: Path | None,
    fallback: SourceLocation | None,
) -> dict[str, Any]:
    result: dict[str, Any] = {
        "ruleId": finding.check,
        "level": _LEVELS[finding.severity],
        "message": {
            "text": f"{finding.object}: {finding.title}. {finding.detail}\n\n"
            f"Fix: {finding.remediation}"
        },
        "partialFingerprints": {"seCheckFinding/v1": fingerprint(finding)},
        "properties": {
            "object": finding.object,
            "severity": finding.severity.label,
            "security-severity": _SECURITY_SEVERITY[finding.severity],
        },
    }
    location = (find_definition(finding, sources) or fallback) if root else None
    if location and root:
        try:
            uri = location.path.resolve().relative_to(root).as_posix()
        except ValueError:
            uri = None
        if uri:
            result["locations"] = [
                {
                    "physicalLocation": {
                        "artifactLocation": {"uri": uri},
                        "region": {"startLine": location.line},
                    }
                }
            ]
    return result

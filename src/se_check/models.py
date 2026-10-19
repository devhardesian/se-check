"""Core data types shared by the checks, the CLI and the MCP server."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import IntEnum
from typing import Any


class Severity(IntEnum):
    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @property
    def label(self) -> str:
        return self.name.lower()

    @classmethod
    def parse(cls, value: str) -> Severity:
        try:
            return cls[value.strip().upper()]
        except KeyError:
            choices = ", ".join(s.label for s in cls)
            raise ValueError(f"unknown severity {value!r} (expected one of: {choices})") from None


@dataclass(frozen=True)
class Finding:
    """One problem found by a check.

    Findings describe database objects (tables, policies, functions), never row data,
    so they are safe to hand to an LLM.
    """

    check: str
    severity: Severity
    object: str
    title: str
    detail: str
    remediation: str
    evidence: dict[str, str] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "check": self.check,
            "severity": self.severity.label,
            "object": self.object,
            "title": self.title,
            "detail": self.detail,
            "remediation": self.remediation,
            "evidence": dict(self.evidence),
        }

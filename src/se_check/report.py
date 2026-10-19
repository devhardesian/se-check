"""Human-readable rendering of an audit report (JSON comes from `AuditReport.to_dict`)."""

from __future__ import annotations

import re
import textwrap
from collections.abc import Callable

from se_check import __version__
from se_check.audit import AuditReport
from se_check.models import Severity
from se_check.probe.model import ProbeCoverage, Skip

_RESET = "\033[0m"
_BOLD = "\033[1m"
_DIM = "\033[2m"
_GREEN = "\033[32m"
_SEVERITY_COLORS = {
    Severity.CRITICAL: "\033[1;31m",
    Severity.HIGH: "\033[31m",
    Severity.MEDIUM: "\033[33m",
    Severity.LOW: "\033[36m",
    Severity.INFO: _DIM,
}
_WIDTH = 92
_FIX_INDENT = "       "  # lines up with the text after "  fix: "
_SQL_STATEMENT = re.compile(r"(alter|create|drop|grant|revoke)\s", re.IGNORECASE)
_NAMED = 5
"""Tables named in a group of skips before "and N more"."""


def _remediation_lines(remediation: str) -> list[str]:
    """Wrap prose and SQL comments; leave SQL statements whole so they stay copy-pasteable."""
    lines: list[str] = []
    for line in remediation.splitlines():
        if _SQL_STATEMENT.match(line):
            lines.append(line)
        elif line.startswith("-- "):
            lines.extend(
                textwrap.wrap(line, width=_WIDTH - len(_FIX_INDENT), subsequent_indent="-- ")
            )
        else:
            lines.extend(textwrap.wrap(line, width=_WIDTH - len(_FIX_INDENT)))
    return lines


def render_text(report: AuditReport, *, color: bool = False) -> str:
    def paint(text: str, code: str) -> str:
        return f"{code}{text}{_RESET}" if color else text

    lines = [
        f"{paint(f'se-check {__version__}', _BOLD)} · PostgreSQL {report.server_version}"
        f" · schemas: {', '.join(report.schemas)}"
    ]
    if report.missing_api_roles:
        lines.append(
            paint(
                f"warning: API role(s) not found: {', '.join(report.missing_api_roles)}. "
                "Is this a Supabase database? Name the right roles with --api-role.",
                _SEVERITY_COLORS[Severity.MEDIUM],
            )
        )
    if report.probe is not None:
        # Before the findings: a probe that reached few tables must not pass for a clean one.
        lines.extend(_probe_headline(report.probe, paint))

    for finding in report.findings:
        lines.append("")
        badge = paint(finding.severity.label.upper().ljust(8), _SEVERITY_COLORS[finding.severity])
        lines.append(
            f"{badge}  {paint(finding.object, _BOLD)}  {paint(f'[{finding.check}]', _DIM)}"
        )
        lines.append(f"  {finding.title}")
        lines.extend(
            textwrap.wrap(finding.detail, width=_WIDTH, initial_indent="  ", subsequent_indent="  ")
        )
        for i, line in enumerate(_remediation_lines(finding.remediation)):
            lines.append((paint("  fix: ", _DIM) if i == 0 else _FIX_INDENT) + line)

    if report.probe is not None:
        lines.append("")
        lines.extend(_probe_lines(report.probe, paint))

    settings_name = report.settings_file.name if report.settings_file else "se-check.toml"
    if report.accepted:
        lines += ["", paint(f"Accepted in {settings_name} ({len(report.accepted)}):", _DIM)]
        for item in report.accepted:
            policy = item.finding.evidence.get("policy")
            subject = f'{item.finding.object} "{policy}"' if policy else item.finding.object
            lines.extend(
                paint(line, _DIM)
                for line in textwrap.wrap(
                    f"{item.finding.check}  {subject}: {item.reason}",
                    width=_WIDTH,
                    initial_indent="  ",
                    subsequent_indent="    ",
                )
            )
    if report.unused_acceptances:
        lines += [
            "",
            paint(
                f"warning: {len(report.unused_acceptances)} accepted finding(s) in "
                f"{settings_name} no longer occur; remove them:",
                _SEVERITY_COLORS[Severity.MEDIUM],
            ),
        ]
        lines.extend(f"  {acceptance.describe()}" for acceptance in report.unused_acceptances)

    lines.append("")
    if report.probe is not None and not report.probe.complete and not report.probe.blocked:
        lines.append(
            paint(
                f'warning: the probe reached only {_reach(report.probe)}: see "Not reached" above.',
                _SEVERITY_COLORS[Severity.MEDIUM],
            )
        )
    if report.findings:
        counts = ", ".join(
            paint(f"{count} {label}", _SEVERITY_COLORS[Severity.parse(label)])
            for label, count in report.counts().items()
            if count
        )
        lines.append(f"{len(report.findings)} findings: {counts}")
    else:
        lines.append(paint("No findings.", _GREEN))
    if report.hidden:
        lines.append(paint(f"{report.hidden} less severe findings hidden by --min-severity.", _DIM))
    if report.findings:
        lines.append(
            paint(
                'Fine on purpose? se-check accept <check> <object> --reason "why"',
                _DIM,
            )
        )
    return "\n".join(lines)


def _wrap(text: str, **kwargs) -> list[str]:
    return textwrap.wrap(text, width=_WIDTH, break_on_hyphens=False, **kwargs)


def _tables(n: int) -> str:
    return f"{n} table{'s' if n != 1 else ''}"


def _reach(coverage: ProbeCoverage) -> str:
    """`3 of 67 tables (0 of 60 tenant-scoped)`."""
    text = f"{len(coverage.reached)} of {_tables(len(coverage.targets))}"
    if coverage.scoped_targets:
        reached = set(coverage.reached)
        scoped = sum(1 for t in coverage.scoped_targets if t in reached)
        text += f" ({scoped} of {len(coverage.scoped_targets)} tenant-scoped)"
    return text


def _probe_headline(coverage: ProbeCoverage, paint: Callable[[str, str], str]) -> list[str]:
    """One paragraph under the title: how much the probe reached, loud when not everything."""
    warn = _SEVERITY_COLORS[Severity.MEDIUM]
    if coverage.blocked:
        text = f"warning: the probe did not run, because {coverage.blocked}."
        return [paint(line, warn) for line in _wrap(text)]
    if not coverage.targets:
        text = "Probe: nothing to try, the API roles hold no privileges on the exposed tables."
        return [paint(line, _DIM) for line in _wrap(text)]
    steps = f"{coverage.steps_run} step{'s' if coverage.steps_run != 1 else ''}"
    if coverage.steps_run != coverage.planned_steps:
        steps = f"{coverage.steps_run} of {coverage.planned_steps} planned steps"
    if coverage.complete:
        text = (
            f"Probe: reached all {_tables(len(coverage.targets))} it could try, with {steps}, "
            "all rolled back. Details at the end."
        )
        return [paint(line, _DIM) for line in _wrap(text)]
    missing = len(coverage.not_reached)
    text = (
        f"warning: the probe reached {_reach(coverage)}, with {steps}: no probe finding on "
        f"the other {missing} says nothing about them."
    )
    groups, _ = _not_reached_groups(coverage)
    root, members = max(groups.items(), key=lambda item: len(item[1]), default=(None, []))
    if root is not None and len(members) > 1 and 2 * len(members) >= missing:
        text += f" {len(members)} of them because {root} got no synthetic row."
    text += ' See "Not reached" at the end.'
    return [paint(line, warn) for line in _wrap(text)]


def _skips_by_table(coverage: ProbeCoverage) -> dict[str, Skip]:
    first: dict[str, Skip] = {}
    for skip in coverage.skipped:
        first.setdefault(skip.table, skip)
    return first


def _not_reached_groups(
    coverage: ProbeCoverage,
) -> tuple[dict[str, list[str]], list[str]]:
    """Tables the probe did not reach, by the table whose missing row started it all
    (root -> those tables, the root first when it is one of them), and the rest."""
    first = _skips_by_table(coverage)

    def root(table: str) -> str:
        seen = {table}
        while (cause := first[table].cause) in first and cause not in seen:
            table = cause
            seen.add(table)
        return table

    groups: dict[str, list[str]] = {}
    unexplained = []
    for table in coverage.not_reached:
        if table in first:
            groups.setdefault(root(table), []).append(table)
        else:
            unexplained.append(table)
    for start, members in groups.items():
        members.sort(key=lambda t: (t != start, t))
    return groups, unexplained


def _probe_lines(coverage: ProbeCoverage, paint: Callable[[str, str], str]) -> list[str]:
    """What the probe tried: without it, "no findings" from the probe says little."""
    if coverage.blocked:
        return []
    lines = _wrap(
        f"Probe: {coverage.statements} statements, all rolled back. "
        f"{coverage.tenancy[:1].upper()}{coverage.tenancy[1:]}."
    )
    if coverage.claims:
        lines += _wrap(f"Personas' JWT claims: {'; '.join(coverage.claims)}.")
    lines = [paint(line, _DIM) for line in lines]

    def item(text: str, indent: str = "  ") -> list[str]:
        return [
            paint(line, _DIM)
            for line in _wrap(text, initial_indent=indent, subsequent_indent=indent + "  ")
        ]

    first = _skips_by_table(coverage)
    groups, unexplained = _not_reached_groups(coverage)
    explained: set[str] = set()
    if coverage.not_reached:
        lines.append(
            paint(
                f"Not reached ({len(coverage.not_reached)} of "
                f"{_tables(len(coverage.targets))}; fix them, or list them in "
                "[probe] skip_tables):",
                _SEVERITY_COLORS[Severity.MEDIUM],
            )
        )
    for start, members in groups.items():
        lines += item(f"{start}: {first[start].reason}")
        explained.add(start)
        others = [t for t in members if t != start]
        if others:
            named = ", ".join(others[:_NAMED])
            more = f" and {len(others) - _NAMED} more" if len(others) > _NAMED else ""
            lines += item(f"{_tables(len(others))} needed its row: {named}{more}", "    ")
            explained.update(others)
    for table in unexplained:
        lines += item(f"{table}: no step ran to a conclusive outcome")
    if coverage.left_out:
        lines += item(f"Left out by [probe] skip_tables: {', '.join(coverage.left_out)}", indent="")
    # Setup that failed (the users, the membership SQL, the hook): it weakens every step.
    causes = {skip.cause for skip in coverage.skipped}
    parents = {stand_in.parent: [] for stand_in in coverage.stand_ins}
    for skip in coverage.skipped:
        if skip.table not in {*explained, *causes, *parents, *coverage.targets}:
            lines += item(f"skipped {skip.table}: {skip.reason}")
    if coverage.stand_ins:
        lines.append(paint("Stand-ins, for references to rows se-check could not make:", _DIM))
    for stand_in in coverage.stand_ins:
        parents[stand_in.parent].append(stand_in)
    for parent, stand_ins in parents.items():
        reason = first[parent].reason if parent in first else "it has no synthetic row"
        lines += item(f"{parent}: {reason}")
        for stand_in in stand_ins:
            lines += item(stand_in.describe(), "    ")
    for observation in coverage.inconclusive:
        step = observation.step
        lines += item(
            f"inconclusive {step.table_name}: {step.command} as {step.persona} "
            f"failed with {observation.sqlstate}"
        )
    return lines

"""Every rule se-check reports on: the static checks, then the dynamic probe's."""

from __future__ import annotations

from collections.abc import Iterable

from se_check.checks import ALL_CHECKS, Check
from se_check.checks.base import Rule
from se_check.probe.rules import PROBE_RULES

ALL_RULES: tuple[Rule, ...] = (*ALL_CHECKS, *PROBE_RULES)
PROBE_RULE_IDS = frozenset(rule.id for rule in PROBE_RULES)


def select_rules(
    ids: Iterable[str] | None, *, probe: bool
) -> tuple[tuple[Check, ...], tuple[Rule, ...]]:
    """The static checks and probe rules with the given ids, or all of them.

    Unknown ids, and probe rules when the probe does not run, raise ValueError.
    """
    probe_rules = PROBE_RULES if probe else ()
    if not ids:
        return ALL_CHECKS, probe_rules
    by_id = {rule.id: rule for rule in ALL_RULES}
    wanted = list(dict.fromkeys(ids))
    unknown = [rule_id for rule_id in wanted if rule_id not in by_id]
    if unknown:
        raise ValueError(f"unknown check(s): {', '.join(unknown)} (available: {', '.join(by_id)})")
    needs_probe = [rule_id for rule_id in wanted if rule_id in PROBE_RULE_IDS]
    if needs_probe and not probe:
        raise ValueError(
            f"{', '.join(needs_probe)} come(s) from the dynamic probe, which is not running here"
        )
    selected = [by_id[rule_id] for rule_id in wanted]
    checks = tuple(rule for rule in selected if isinstance(rule, Check))
    return checks, tuple(rule for rule in selected if rule.id in PROBE_RULE_IDS)

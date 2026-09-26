"""Suppression config: silence known-fine findings by rule and pattern.

A history file tends to accumulate the same "false positive" over and
over -- a fixture with a fake password, a script that legitimately does
`rm -rf` on a scratch directory it owns. Re-reviewing the same line on
every run is noise, so a suppression file lets you say "the
secret-in-history rule doesn't need to flag lines matching
TEST_PASSWORD=" once instead of every time.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Iterable, List

from .rules import Finding


@dataclass
class Suppression:
    rule_id: str  # "*" matches any rule
    pattern: "re.Pattern[str]"


class SuppressionConfigError(ValueError):
    """The suppression file is present but malformed."""


def parse_suppressions(lines: Iterable[str]) -> List[Suppression]:
    """Parse suppression file lines.

    Each non-blank, non-comment line is `<rule-id or *> <regex>`, e.g.:

        secret-in-history  TEST_PASSWORD=
        *                   rm -rf /tmp/scratch-\\d+

    The pattern is matched with re.search against the raw command text,
    so it doesn't need to anchor the whole line.
    """
    suppressions = []
    for raw in lines:
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        rule_id, sep, pattern_text = line.partition(" ")
        pattern_text = pattern_text.strip()
        if not sep or not pattern_text:
            raise SuppressionConfigError(
                f"malformed suppression line (expected '<rule-id or *> <pattern>'): {raw!r}"
            )
        try:
            pattern = re.compile(pattern_text)
        except re.error as exc:
            raise SuppressionConfigError(f"invalid regex {pattern_text!r}: {exc}") from exc
        suppressions.append(Suppression(rule_id, pattern))
    return suppressions


def load_suppressions(path: str) -> List[Suppression]:
    with open(path, "r", encoding="utf-8") as fh:
        return parse_suppressions(fh)


def is_suppressed(finding: Finding, text: str, suppressions: List[Suppression]) -> bool:
    for suppression in suppressions:
        if suppression.rule_id not in ("*", finding.rule_id):
            continue
        if suppression.pattern.search(text):
            return True
    return False

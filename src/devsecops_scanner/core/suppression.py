"""Inline suppressions.

A finding is suppressed by a directive comment on the same line, or on the line
directly above when that line contains nothing but the comment::

    value = eval(expr)  # dsscan: ignore[SAST-001]
    # dsscan: ignore
    os.system(command)

``ignore`` without brackets suppresses every rule; ``ignore[A, B]`` only those rules.
Suppressions are counted and reported, so they stay auditable.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Final

from devsecops_scanner.core.filesystem import SourceFile
from devsecops_scanner.core.models import Finding

_DIRECTIVE: Final = re.compile(
    r"(?:#|//|--|/\*|<!--)\s*dsscan:\s*ignore(?:\[(?P<rules>[^\]]*)\])?",
    re.IGNORECASE,
)
_COMMENT_ONLY: Final = re.compile(r"^\s*(?:#|//|--|/\*|<!--)")


@dataclass(frozen=True, slots=True)
class Directive:
    """A parsed ``dsscan: ignore`` comment."""

    rule_ids: frozenset[str]  # empty means "all rules"

    def covers(self, rule_id: str) -> bool:
        """Return ``True`` when this directive silences ``rule_id``."""
        return not self.rule_ids or rule_id.casefold() in self.rule_ids


def parse_directive(line: str) -> Directive | None:
    """Parse a directive from one source line, or return ``None``."""
    match = _DIRECTIVE.search(line)
    if match is None:
        return None
    raw = match.group("rules")
    if raw is None:
        return Directive(rule_ids=frozenset())
    ids = frozenset(part.strip().casefold() for part in raw.split(",") if part.strip())
    # ``ignore[]`` (empty brackets) silences nothing: it must not become a wildcard.
    return Directive(rule_ids=ids or frozenset({"\x00"}))


def is_suppressed(finding: Finding, source: SourceFile) -> bool:
    """Return ``True`` when a directive on the finding's line (or above) covers it."""
    line_number = finding.location.line

    same_line = parse_directive(source.line_text(line_number))
    if same_line is not None and same_line.covers(finding.rule_id):
        return True

    previous = source.line_text(line_number - 1)
    if _COMMENT_ONLY.match(previous):
        above = parse_directive(previous)
        return above is not None and above.covers(finding.rule_id)
    return False

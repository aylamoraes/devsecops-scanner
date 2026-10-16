"""Secret analyzer: scans every text line against the secret patterns.

Security properties:

* The secret value is never stored in a finding, a message or a snippet. Snippets show
  the source line with every detected secret masked.
* ``match_key`` is the column, never a hash of the secret: a hash of a weak secret
  could be reversed with a dictionary attack by anyone who reads the report.
"""

from __future__ import annotations

from collections.abc import Iterable, Iterator, Sequence
from dataclasses import dataclass

from devsecops_scanner.core.analyzer import AnalysisItem, Analyzer
from devsecops_scanner.core.filesystem import SourceFile
from devsecops_scanner.core.models import Finding, FindingKind, Location, RuleInfo
from devsecops_scanner.secret_detection.heuristics import (
    KNOWN_EXAMPLE_VALUES,
    is_placeholder,
    looks_like_non_secret,
    redact,
    shannon_entropy,
)
from devsecops_scanner.secret_detection.patterns import DEFAULT_PATTERNS, SecretPattern

_SKIPPED_SUFFIXES = (".svg", ".map", ".min.js", ".min.css")
_SNIPPET_LIMIT = 160
_REMEDIATION = (
    "Revoke and rotate this credential now, remove it from the code and from the Git "
    "history, and load it from a secret manager or an environment variable instead."
)


@dataclass(frozen=True, slots=True)
class _Hit:
    pattern: SecretPattern
    start: int
    end: int
    secret: str


class SecretAnalyzer(Analyzer):
    """Detects hard-coded credentials in any text file."""

    def __init__(self, patterns: Sequence[SecretPattern] = DEFAULT_PATTERNS) -> None:
        self._patterns = tuple(patterns)

    @property
    def name(self) -> str:
        return "secrets"

    def accepts(self, path: str) -> bool:
        return not path.lower().endswith(_SKIPPED_SUFFIXES)

    def rules(self) -> tuple[RuleInfo, ...]:
        return tuple(
            RuleInfo(
                rule_id=pattern.rule_id,
                kind=FindingKind.SECRET,
                severity=pattern.severity,
                title=pattern.title,
                cwe="CWE-798",
            )
            for pattern in self._patterns
        )

    def analyze(self, source: SourceFile) -> Iterable[AnalysisItem]:
        return list(self._scan(source))

    def _scan(self, source: SourceFile) -> Iterator[Finding]:
        for line_number, line in enumerate(source.lines, start=1):
            if len(line) < 8:
                continue
            hits = self._hits(line)
            if not hits:
                continue
            # Build the snippet once, with *all* secrets of the line masked, so a finding
            # for one secret cannot leak another secret on the same line.
            snippet = _masked_line(line, hits)[:_SNIPPET_LIMIT] or None
            for hit in hits:
                yield Finding(
                    rule_id=hit.pattern.rule_id,
                    kind=FindingKind.SECRET,
                    severity=hit.pattern.severity,
                    title=hit.pattern.title,
                    message=(
                        f"Possible {hit.pattern.title} found in the source. "
                        "The value is redacted in this report."
                    ),
                    location=Location(path=source.path, line=line_number, column=hit.start + 1),
                    remediation=_REMEDIATION,
                    cwe="CWE-798",
                    snippet=snippet,
                    match_key=str(hit.start + 1),
                )

    def _hits(self, line: str) -> list[_Hit]:
        accepted: list[_Hit] = []
        for pattern in self._patterns:
            for match in pattern.regex.finditer(line):
                secret = match.group(pattern.secret_group)
                start, end = match.span(pattern.secret_group)
                if not _is_credible(pattern, secret):
                    continue
                if any(start < other.end and end > other.start for other in accepted):
                    continue  # already reported by a more specific pattern
                accepted.append(_Hit(pattern, start, end, secret))
        return sorted(accepted, key=lambda hit: hit.start)


def _is_credible(pattern: SecretPattern, secret: str) -> bool:
    if secret in KNOWN_EXAMPLE_VALUES:
        return False
    if pattern.skip_placeholders and (is_placeholder(secret) or looks_like_non_secret(secret)):
        return False
    return pattern.min_entropy is None or shannon_entropy(secret) >= pattern.min_entropy


def _masked_line(line: str, hits: Sequence[_Hit]) -> str:
    """Replace every sensitive span with its redacted form (right to left, keeping offsets)."""
    masked = line
    for hit in sorted(hits, key=lambda h: h.start, reverse=True):
        if hit.pattern.mask:
            masked = masked[: hit.start] + redact(hit.secret) + masked[hit.end :]
    return masked.strip()

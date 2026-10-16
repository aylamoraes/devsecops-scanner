"""Domain models shared by every analyzer, the engine and the reporters.

All models are immutable (``frozen``) and reject unknown fields (``extra="forbid"``),
so a typo or an unexpected payload fails loudly instead of being silently ignored.
"""

from __future__ import annotations

import hashlib
from enum import StrEnum
from pathlib import PurePosixPath
from typing import Final

from pydantic import BaseModel, ConfigDict, Field, field_validator


class FrozenModel(BaseModel):
    """Base class: immutable, strict about unknown fields, trims string whitespace."""

    model_config = ConfigDict(frozen=True, extra="forbid", str_strip_whitespace=True)


class Severity(StrEnum):
    """Finding severity, ordered from least to most severe."""

    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def rank(self) -> int:
        """Numeric rank used for ordering (higher is more severe)."""
        return _SEVERITY_RANK[self]

    def at_least(self, threshold: Severity) -> bool:
        """Return ``True`` when this severity is equal to or above ``threshold``."""
        return self.rank >= threshold.rank


_SEVERITY_RANK: Final[dict[Severity, int]] = {
    Severity.INFO: 0,
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
    Severity.CRITICAL: 4,
}


class FindingKind(StrEnum):
    """Which engine produced a finding."""

    SAST = "sast"
    SCA = "sca"
    SECRET = "secret"  # noqa: S105 - enum label, not a credential


class Location(FrozenModel):
    """A position inside the scanned tree.

    ``path`` is always relative to the scan root and uses forward slashes, so reports
    are identical on Windows and Linux and never leak the absolute path of the runner.
    """

    path: str = Field(min_length=1, max_length=1024)
    line: int = Field(ge=1)
    column: int | None = Field(default=None, ge=1)

    @field_validator("path")
    @classmethod
    def _must_be_relative_posix(cls, value: str) -> str:
        if "\\" in value:
            raise ValueError("path must use forward slashes")
        pure = PurePosixPath(value)
        if pure.is_absolute() or ".." in pure.parts:
            raise ValueError("path must be relative and must not contain '..'")
        return value


class Finding(FrozenModel):
    """A single security finding."""

    rule_id: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]*$", max_length=100)
    kind: FindingKind
    severity: Severity
    title: str = Field(min_length=1, max_length=200)
    message: str = Field(min_length=1, max_length=1000)
    location: Location
    remediation: str | None = Field(default=None, max_length=1000)
    cwe: str | None = Field(default=None, pattern=r"^CWE-\d{1,5}$")
    snippet: str | None = Field(default=None, max_length=300)
    # Disambiguates two findings of the same rule on the same line (for example the
    # column, or ``package@version``). It must never be derived from a secret value.
    match_key: str = Field(default="", max_length=200)

    def fingerprint(self) -> str:
        """Stable identifier, usable for deduplication and baselines.

        It depends on the rule, the file, the line and ``match_key``. It does not
        depend on the message text, so rewording a message does not break baselines.
        """
        raw = "|".join((self.rule_id, self.location.path, str(self.location.line), self.match_key))
        return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:32]


class RuleInfo(FrozenModel):
    """Static description of a rule, used by ``dsscan rules``."""

    rule_id: str
    kind: FindingKind
    severity: Severity
    title: str
    cwe: str | None = None


class IssueLevel(StrEnum):
    """Severity of a scan issue (a problem with the scan itself, not with the code)."""

    WARNING = "warning"
    ERROR = "error"


class ScanIssue(FrozenModel):
    """A problem that affected coverage: unreadable file, parse error, crashed analyzer."""

    level: IssueLevel
    source: str = Field(min_length=1, max_length=50)
    message: str = Field(min_length=1, max_length=500)
    path: str | None = Field(default=None, max_length=1024)


class ScanResult(FrozenModel):
    """Everything a reporter needs."""

    findings: tuple[Finding, ...] = ()
    issues: tuple[ScanIssue, ...] = ()
    files_scanned: int = Field(default=0, ge=0)
    suppressed: int = Field(default=0, ge=0)

    def count_by_severity(self) -> dict[Severity, int]:
        """Number of findings per severity; every severity is present (possibly 0)."""
        counts = dict.fromkeys(Severity, 0)
        for finding in self.findings:
            counts[finding.severity] += 1
        return counts

    def exceeds(self, threshold: Severity | None) -> bool:
        """``True`` when at least one finding is at or above ``threshold``.

        ``None`` means "never fail", so the result is always ``False``.
        """
        if threshold is None:
            return False
        return any(f.severity.at_least(threshold) for f in self.findings)

    @property
    def has_errors(self) -> bool:
        """``True`` when the scan was incomplete because of an error-level issue."""
        return any(issue.level is IssueLevel.ERROR for issue in self.issues)

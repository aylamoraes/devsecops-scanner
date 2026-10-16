"""The :class:`Analyzer` contract (Strategy pattern).

The engine knows only this abstraction. SAST, SCA and secret detection are three
interchangeable strategies; adding a fourth one does not touch the engine.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Iterable

from devsecops_scanner.core.filesystem import SourceFile
from devsecops_scanner.core.models import Finding, RuleInfo, ScanIssue

AnalysisItem = Finding | ScanIssue


class Analyzer(ABC):
    """Inspects one file at a time and reports findings."""

    @property
    @abstractmethod
    def name(self) -> str:
        """Short identifier used in issue reports (``sast``, ``sca``, ``secrets``)."""

    @abstractmethod
    def accepts(self, path: str) -> bool:
        """Return ``True`` when this analyzer wants to look at ``path``."""

    @abstractmethod
    def analyze(self, source: SourceFile) -> Iterable[AnalysisItem]:
        """Analyze one file.

        May yield :class:`Finding` and :class:`ScanIssue` objects. Raise
        :class:`~devsecops_scanner.core.errors.FileAnalysisError` for an expected,
        non-fatal problem with this file (for example a syntax error).
        """

    @abstractmethod
    def rules(self) -> tuple[RuleInfo, ...]:
        """Static description of the rules this analyzer applies."""

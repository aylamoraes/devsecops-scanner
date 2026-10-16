"""The scan engine: walks files once and dispatches them to analyzers."""

from __future__ import annotations

import logging
from collections.abc import Sequence
from pathlib import Path

from devsecops_scanner.core.analyzer import Analyzer
from devsecops_scanner.core.config import ScanConfig
from devsecops_scanner.core.errors import FileAnalysisError
from devsecops_scanner.core.filesystem import SourceFile, iter_sources
from devsecops_scanner.core.models import (
    Finding,
    IssueLevel,
    ScanIssue,
    ScanResult,
)
from devsecops_scanner.core.suppression import is_suppressed

logger = logging.getLogger(__name__)


class ScanEngine:
    """Orchestrates a scan.

    Design decisions:

    * One pass over the file tree; every analyzer sees each file it accepts.
    * An analyzer that crashes never aborts the scan, but the crash is recorded as an
      *error* issue (so CI can fail closed) instead of being swallowed.
    * Output is deterministic: findings are deduplicated by fingerprint and sorted by
      severity, path, line and rule.
    """

    def __init__(self, analyzers: Sequence[Analyzer]) -> None:
        self._analyzers = tuple(analyzers)

    @property
    def analyzers(self) -> tuple[Analyzer, ...]:
        """The analyzers this engine dispatches to."""
        return self._analyzers

    def scan(self, root: Path, config: ScanConfig) -> ScanResult:
        """Scan ``root`` (a directory or a single file) and return the result."""
        findings: dict[str, Finding] = {}
        issues: list[ScanIssue] = []
        files_scanned = 0
        suppressed = 0

        for item in iter_sources(root, config):
            if isinstance(item, ScanIssue):
                issues.append(item)
                continue

            files_scanned += 1
            for analyzer in self._analyzers:
                if not analyzer.accepts(item.path):
                    continue
                for produced in self._run(analyzer, item, issues):
                    if isinstance(produced, ScanIssue):
                        issues.append(produced)
                    elif is_suppressed(produced, item):
                        suppressed += 1
                    else:
                        findings.setdefault(produced.fingerprint(), produced)

        ordered = sorted(
            findings.values(),
            key=lambda f: (-f.severity.rank, f.location.path, f.location.line, f.rule_id),
        )
        return ScanResult(
            findings=tuple(ordered),
            issues=tuple(issues),
            files_scanned=files_scanned,
            suppressed=suppressed,
        )

    @staticmethod
    def _run(
        analyzer: Analyzer, source: SourceFile, issues: list[ScanIssue]
    ) -> list[Finding | ScanIssue]:
        try:
            return list(analyzer.analyze(source))
        except FileAnalysisError as exc:
            issues.append(
                ScanIssue(
                    level=IssueLevel.WARNING,
                    source=analyzer.name,
                    path=source.path,
                    message=str(exc) or "file could not be analyzed",
                )
            )
        except Exception as exc:
            # A bug in an analyzer must not hide the findings of the other analyzers,
            # but it must not pass silently either. Only the exception *type* goes in
            # the report: the message could contain file content.
            logger.error(
                "analyzer %s crashed on %s (%s)", analyzer.name, source.path, type(exc).__name__
            )
            logger.debug("analyzer crash details", exc_info=True)
            issues.append(
                ScanIssue(
                    level=IssueLevel.ERROR,
                    source=analyzer.name,
                    path=source.path,
                    message=f"analyzer crashed ({type(exc).__name__}); results are incomplete",
                )
            )
        return []

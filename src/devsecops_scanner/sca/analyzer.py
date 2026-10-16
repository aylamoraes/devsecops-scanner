"""SCA analyzer: matches pinned dependencies against the advisory database."""

from __future__ import annotations

from collections.abc import Iterable, Sequence

from packaging.version import InvalidVersion, Version

from devsecops_scanner.core.analyzer import AnalysisItem, Analyzer
from devsecops_scanner.core.filesystem import SourceFile
from devsecops_scanner.core.models import (
    Finding,
    FindingKind,
    IssueLevel,
    RuleInfo,
    ScanIssue,
)
from devsecops_scanner.sca.advisories import AdvisoryDatabase
from devsecops_scanner.sca.models import Advisory, Dependency, VersionRange, normalize_name
from devsecops_scanner.sca.parsers import DEFAULT_PARSERS, ManifestParser


class ScaAnalyzer(Analyzer):
    """Reports dependencies whose exact version falls inside an advisory's affected range."""

    def __init__(
        self,
        database: AdvisoryDatabase,
        parsers: Sequence[ManifestParser] = DEFAULT_PARSERS,
    ) -> None:
        self._database = database
        self._parsers = tuple(parsers)

    @property
    def name(self) -> str:
        return "sca"

    def accepts(self, path: str) -> bool:
        return any(parser.matches(path) for parser in self._parsers)

    def rules(self) -> tuple[RuleInfo, ...]:
        return tuple(
            RuleInfo(
                rule_id=advisory.id,
                kind=FindingKind.SCA,
                severity=advisory.severity,
                title=f"{advisory.package}: {advisory.summary}"[:200],
                cwe=advisory.cwe,
            )
            for advisory in self._database.advisories()
        )

    def analyze(self, source: SourceFile) -> Iterable[AnalysisItem]:
        parser = next(p for p in self._parsers if p.matches(source.path))
        parsed = parser.parse(source)

        items: list[AnalysisItem] = []
        unchecked = parsed.unchecked
        for dependency in parsed.dependencies:
            try:
                version = Version(dependency.version)
            except InvalidVersion:
                unchecked += 1
                continue
            for advisory in self._database.lookup(dependency.ecosystem, dependency.name):
                matched = advisory.matching_range(version)
                if matched is not None:
                    items.append(_to_finding(advisory, dependency, matched))

        if unchecked:
            items.append(
                ScanIssue(
                    level=IssueLevel.WARNING,
                    source=self.name,
                    path=source.path,
                    message=(
                        f"{unchecked} dependency entries were not checked "
                        "(not pinned to an exact, standard version)"
                    ),
                )
            )
        return items


def _to_finding(advisory: Advisory, dependency: Dependency, matched: VersionRange) -> Finding:
    if matched.fixed is not None:
        remediation = f"Upgrade {dependency.name} to {matched.fixed} or later."
    else:
        remediation = (
            "No fixed version is published for this advisory: replace the package or "
            "apply a vendor-recommended mitigation."
        )
    normalized = normalize_name(dependency.ecosystem, dependency.name)
    return Finding(
        rule_id=advisory.id,
        kind=FindingKind.SCA,
        severity=advisory.severity,
        title=f"Vulnerable dependency: {dependency.name} {dependency.version}"[:200],
        message=f"{advisory.id}: {advisory.summary}",
        location=dependency.location,
        remediation=remediation,
        cwe=advisory.cwe,
        snippet=f"{dependency.name} {dependency.version}"[:300],
        match_key=f"{normalized}@{dependency.version}",
    )

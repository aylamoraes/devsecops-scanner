"""Unit and integration tests for the scan engine."""

from __future__ import annotations

from collections.abc import Iterable

import pytest

from devsecops_scanner.core.analyzer import AnalysisItem
from devsecops_scanner.core.config import ScanConfig
from devsecops_scanner.core.engine import ScanEngine
from devsecops_scanner.core.errors import FileAnalysisError
from devsecops_scanner.core.filesystem import SourceFile
from devsecops_scanner.core.models import IssueLevel, ScanIssue, Severity
from tests.conftest import WriteTree
from tests.helpers import CrashingAnalyzer, StaticAnalyzer, make_finding


class TestDispatch:
    def test_counts_files_and_returns_findings(
        self, write_tree: WriteTree, config: ScanConfig
    ) -> None:
        root = write_tree({"a.py": "x = 1\n", "b.py": "y = 2\n", "c.txt": "z\n"})
        analyzer = StaticAnalyzer([make_finding(match_key="k")])
        result = ScanEngine([analyzer]).scan(root, config)
        assert result.files_scanned == 3
        # Same finding fingerprint for both .py files => deduplicated to one.
        assert len(result.findings) == 1

    def test_analyzer_only_sees_files_it_accepts(
        self, write_tree: WriteTree, config: ScanConfig
    ) -> None:
        seen: list[str] = []

        class Recorder(StaticAnalyzer):
            def analyze(self, source: SourceFile) -> Iterable[AnalysisItem]:
                seen.append(source.path)
                return []

        root = write_tree({"a.py": "x\n", "b.txt": "y\n"})
        ScanEngine([Recorder([])]).scan(root, config)
        assert seen == ["a.py"]

    def test_no_analyzers_means_no_findings(
        self, write_tree: WriteTree, config: ScanConfig
    ) -> None:
        result = ScanEngine([]).scan(write_tree({"a.py": "x\n"}), config)
        assert result.findings == ()
        assert result.files_scanned == 1


class TestOrderingAndDedup:
    def test_findings_are_sorted_by_severity_then_location(
        self, write_tree: WriteTree, config: ScanConfig
    ) -> None:
        findings = [
            make_finding(rule_id="R-LOW", severity=Severity.LOW, line=1),
            make_finding(rule_id="R-CRIT", severity=Severity.CRITICAL, line=9),
            make_finding(rule_id="R-HIGH-B", severity=Severity.HIGH, line=5),
            make_finding(rule_id="R-HIGH-A", severity=Severity.HIGH, line=2),
        ]
        root = write_tree({"a.py": "x\n"})
        result = ScanEngine([StaticAnalyzer(findings)]).scan(root, config)
        assert [f.rule_id for f in result.findings] == [
            "R-CRIT",
            "R-HIGH-A",
            "R-HIGH-B",
            "R-LOW",
        ]

    def test_duplicates_from_two_analyzers_are_merged(
        self, write_tree: WriteTree, config: ScanConfig
    ) -> None:
        finding = make_finding()
        engine = ScanEngine([StaticAnalyzer([finding], "one"), StaticAnalyzer([finding], "two")])
        result = engine.scan(write_tree({"a.py": "x\n"}), config)
        assert len(result.findings) == 1

    def test_output_is_deterministic(self, write_tree: WriteTree, config: ScanConfig) -> None:
        root = write_tree({"b.py": "x\n", "a.py": "y\n"})
        engine = ScanEngine([StaticAnalyzer([make_finding(line=3), make_finding(line=1)])])
        assert engine.scan(root, config) == engine.scan(root, config)


class TestSuppression:
    def test_suppressed_findings_are_counted_not_reported(
        self, write_tree: WriteTree, config: ScanConfig
    ) -> None:
        root = write_tree({"a.py": "value = eval(x)  # dsscan: ignore[SAST-001]\n"})
        result = ScanEngine([StaticAnalyzer([make_finding(line=1)])]).scan(root, config)
        assert result.findings == ()
        assert result.suppressed == 1

    def test_unsuppressed_findings_remain(self, write_tree: WriteTree, config: ScanConfig) -> None:
        root = write_tree({"a.py": "value = eval(x)\n"})
        result = ScanEngine([StaticAnalyzer([make_finding(line=1)])]).scan(root, config)
        assert len(result.findings) == 1
        assert result.suppressed == 0


class TestFailureIsolation:
    def test_expected_problem_becomes_a_warning(
        self, write_tree: WriteTree, config: ScanConfig
    ) -> None:
        engine = ScanEngine([CrashingAnalyzer(FileAnalysisError("bad syntax"))])
        result = engine.scan(write_tree({"a.py": "x\n"}), config)
        assert [i.level for i in result.issues] == [IssueLevel.WARNING]
        assert result.issues[0].message == "bad syntax"
        assert result.issues[0].path == "a.py"
        assert result.has_errors is False

    def test_unexpected_crash_becomes_an_error_without_leaking_the_message(
        self, write_tree: WriteTree, config: ScanConfig
    ) -> None:
        marker = "FILE-CONTENT-MARKER"
        engine = ScanEngine([CrashingAnalyzer(RuntimeError(marker))])
        result = engine.scan(write_tree({"a.py": "x\n"}), config)
        assert result.has_errors is True
        issue = result.issues[0]
        assert issue.level is IssueLevel.ERROR
        assert "RuntimeError" in issue.message
        assert marker not in issue.message

    def test_a_crash_does_not_hide_other_analyzers(
        self, write_tree: WriteTree, config: ScanConfig
    ) -> None:
        engine = ScanEngine(
            [CrashingAnalyzer(RuntimeError("boom")), StaticAnalyzer([make_finding()])]
        )
        result = engine.scan(write_tree({"a.py": "x\n"}), config)
        assert len(result.findings) == 1
        assert result.has_errors is True

    def test_issues_yielded_by_an_analyzer_are_kept(
        self, write_tree: WriteTree, config: ScanConfig
    ) -> None:
        issue = ScanIssue(level=IssueLevel.WARNING, source="static", message="heads up")
        result = ScanEngine([StaticAnalyzer([issue])]).scan(write_tree({"a.py": "x\n"}), config)
        assert result.issues == (issue,)


@pytest.mark.parametrize("name", ["sast", "sca", "secrets"])
def test_analyzer_names_are_the_documented_ones(name: str) -> None:
    from devsecops_scanner.bootstrap import build_analyzers

    assert name in {a.name for a in build_analyzers(ScanConfig())}


class TestEngineBasics:
    def test_exposes_its_analyzers(self) -> None:
        analyzers = [StaticAnalyzer([], "one"), StaticAnalyzer([], "two")]
        assert ScanEngine(analyzers).analyzers == tuple(analyzers)

    def test_filesystem_issues_are_reported_and_scanning_continues(
        self, write_tree: WriteTree
    ) -> None:
        root = write_tree({"big.py": "x = 1\n" * 1000, "ok.py": "y = 2\n"})
        config = ScanConfig(max_file_size_bytes=1024)
        result = ScanEngine([StaticAnalyzer([])]).scan(root, config)
        assert result.files_scanned == 1
        assert [i.path for i in result.issues] == ["big.py"]
        assert result.issues[0].source == "filesystem"

"""Unit tests for the domain models."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from devsecops_scanner.core.models import (
    Finding,
    IssueLevel,
    Location,
    ScanIssue,
    ScanResult,
    Severity,
)
from tests.helpers import make_finding


class TestSeverity:
    def test_ordering(self) -> None:
        ranks = [s.rank for s in (Severity.INFO, Severity.LOW, Severity.MEDIUM, Severity.HIGH)]
        assert ranks == sorted(ranks)
        assert Severity.CRITICAL.rank > Severity.HIGH.rank

    @pytest.mark.parametrize(
        ("severity", "threshold", "expected"),
        [
            (Severity.CRITICAL, Severity.HIGH, True),
            (Severity.HIGH, Severity.HIGH, True),
            (Severity.MEDIUM, Severity.HIGH, False),
            (Severity.INFO, Severity.INFO, True),
        ],
    )
    def test_at_least(self, severity: Severity, threshold: Severity, expected: bool) -> None:
        assert severity.at_least(threshold) is expected

    def test_string_values(self) -> None:
        assert Severity("high") is Severity.HIGH
        as_text: str = Severity.HIGH
        assert as_text == "high"


class TestLocation:
    def test_valid(self) -> None:
        location = Location(path="src/app.py", line=3, column=5)
        assert (location.path, location.line, location.column) == ("src/app.py", 3, 5)

    @pytest.mark.parametrize(
        "path",
        ["/etc/passwd", "../outside.py", "a/../b.py", "dir\\file.py", ""],
    )
    def test_rejects_unsafe_paths(self, path: str) -> None:
        with pytest.raises(ValidationError):
            Location(path=path, line=1)

    @pytest.mark.parametrize("line", [0, -1])
    def test_rejects_non_positive_line(self, line: int) -> None:
        with pytest.raises(ValidationError):
            Location(path="a.py", line=line)

    def test_rejects_non_positive_column(self) -> None:
        with pytest.raises(ValidationError):
            Location(path="a.py", line=1, column=0)


class TestFinding:
    def test_is_immutable(self) -> None:
        finding = make_finding()
        with pytest.raises(ValidationError):
            finding.line = 5  # type: ignore[attr-defined]

    def test_rejects_unknown_fields(self) -> None:
        data = make_finding().model_dump()
        data["surprise"] = "value"
        with pytest.raises(ValidationError):
            Finding.model_validate(data)

    @pytest.mark.parametrize("rule_id", ["has space", "", "-leading-dash", "semi;colon"])
    def test_rejects_malformed_rule_id(self, rule_id: str) -> None:
        with pytest.raises(ValidationError):
            make_finding(rule_id=rule_id)

    @pytest.mark.parametrize("cwe", ["CWE-ABC", "cwe-79", "79", "CWE-"])
    def test_rejects_malformed_cwe(self, cwe: str) -> None:
        with pytest.raises(ValidationError):
            make_finding(cwe=cwe)

    def test_accepts_osv_style_rule_ids(self) -> None:
        assert make_finding(rule_id="GHSA-abcd-1234-wxyz").rule_id == "GHSA-abcd-1234-wxyz"
        assert make_finding(rule_id="CVE-2023-32681").rule_id == "CVE-2023-32681"


class TestFingerprint:
    def test_is_stable(self) -> None:
        assert make_finding().fingerprint() == make_finding().fingerprint()

    @pytest.mark.parametrize(
        "changes",
        [{"line": 2}, {"path": "other.py"}, {"rule_id": "SAST-002"}, {"match_key": "7"}],
    )
    def test_changes_with_identity_fields(self, changes: dict[str, object]) -> None:
        assert make_finding().fingerprint() != make_finding(**changes).fingerprint()  # type: ignore[arg-type]

    def test_ignores_message_and_snippet(self) -> None:
        original = make_finding()
        reworded = make_finding(message="Different wording.", snippet="other code")
        assert original.fingerprint() == reworded.fingerprint()

    def test_has_fixed_length(self) -> None:
        assert len(make_finding().fingerprint()) == 32


class TestScanResult:
    def test_count_by_severity_has_every_level(self) -> None:
        result = ScanResult(
            findings=(
                make_finding(severity=Severity.HIGH),
                make_finding(severity=Severity.HIGH, line=2),
                make_finding(severity=Severity.LOW, line=3),
            )
        )
        counts = result.count_by_severity()
        assert counts[Severity.HIGH] == 2
        assert counts[Severity.LOW] == 1
        assert counts[Severity.CRITICAL] == 0
        assert set(counts) == set(Severity)

    @pytest.mark.parametrize(
        ("threshold", "expected"),
        [
            (Severity.INFO, True),
            (Severity.MEDIUM, True),
            (Severity.HIGH, False),
            (Severity.CRITICAL, False),
            (None, False),
        ],
    )
    def test_exceeds(self, threshold: Severity | None, expected: bool) -> None:
        result = ScanResult(findings=(make_finding(severity=Severity.MEDIUM),))
        assert result.exceeds(threshold) is expected

    def test_empty_result_never_exceeds(self) -> None:
        assert ScanResult().exceeds(Severity.INFO) is False

    def test_has_errors_only_for_error_level(self) -> None:
        warning = ScanIssue(level=IssueLevel.WARNING, source="sast", message="w")
        error = ScanIssue(level=IssueLevel.ERROR, source="sast", message="e")
        assert ScanResult(issues=(warning,)).has_errors is False
        assert ScanResult(issues=(warning, error)).has_errors is True

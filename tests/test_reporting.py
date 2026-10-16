"""Unit tests for the text, JSON and SARIF reporters and the reporter factory."""

from __future__ import annotations

import json
from typing import Any

import pytest

from devsecops_scanner import __version__
from devsecops_scanner.core.errors import ConfigError
from devsecops_scanner.core.models import IssueLevel, ScanIssue, ScanResult, Severity
from devsecops_scanner.reporting import (
    REPORTER_NAMES,
    JsonReporter,
    SarifReporter,
    TextReporter,
    get_reporter,
)
from devsecops_scanner.reporting.text import sanitize
from tests.helpers import make_finding


@pytest.fixture
def result() -> ScanResult:
    return ScanResult(
        findings=(
            make_finding(rule_id="SAST-001", severity=Severity.CRITICAL, line=10, column=5),
            make_finding(rule_id="SAST-001", severity=Severity.CRITICAL, path="b.py", line=2),
            make_finding(rule_id="SAST-004", severity=Severity.MEDIUM, line=3, cwe="CWE-327"),
            make_finding(rule_id="SECRET-JWT", severity=Severity.LOW, line=7, cwe=None),
        ),
        issues=(
            ScanIssue(level=IssueLevel.WARNING, source="sast", path="bad.py", message="oops"),
        ),
        files_scanned=12,
        suppressed=3,
    )


class TestFactory:
    def test_known_names(self) -> None:
        assert REPORTER_NAMES == ("text", "json", "sarif")
        assert isinstance(get_reporter("text"), TextReporter)
        assert isinstance(get_reporter("json"), JsonReporter)
        assert isinstance(get_reporter("sarif"), SarifReporter)

    def test_unknown_name(self) -> None:
        with pytest.raises(ConfigError, match="unknown report format"):
            get_reporter("xml")


class TestSanitize:
    @pytest.mark.parametrize(
        ("raw", "expected"),
        [
            ("plain text", "plain text"),
            ("a\nb", "a?b"),
            ("a\r\nb", "a??b"),
            ("\x1b[31mred\x1b[0m", "?[31mred?[0m"),
            ("tab\there", "tab?here"),
            ("nul\x00byte", "nul?byte"),
            ("c1\x85control", "c1?control"),
            ("ação", "ação"),
        ],
    )
    def test_replaces_control_characters(self, raw: str, expected: str) -> None:
        assert sanitize(raw) == expected


class TestTextReporter:
    def test_contains_header_summary_and_findings(self, result: ScanResult) -> None:
        out = TextReporter().render(result)
        assert out.startswith(f"devsecops-scanner {__version__}\n")
        assert "Scanned 12 file(s): 4 finding(s), 3 suppressed." in out
        assert "[CRITICAL] SAST-001 app/module.py:10:5" in out
        assert "[CRITICAL] SAST-001 b.py:2:1" in out
        assert "Fix: Fix it." in out
        assert "Ref: CWE-327" in out
        assert "Summary: critical 2 | high 0 | medium 1 | low 1 | info 0" in out

    def test_lists_scan_issues(self, result: ScanResult) -> None:
        out = TextReporter().render(result)
        assert "Scan issues (coverage may be incomplete):" in out
        assert "[warning] (sast) bad.py: oops" in out

    def test_clean_scan(self) -> None:
        out = TextReporter().render(ScanResult(files_scanned=5))
        assert "Scanned 5 file(s): 0 finding(s), 0 suppressed." in out
        assert "Scan issues" not in out

    def test_hostile_content_cannot_inject_escape_codes_or_fake_lines(self) -> None:
        hostile = make_finding(
            message="line one\n[CRITICAL] FAKE-RULE injected",
            snippet="\x1b[2J\x1b[31mcleared",
        )
        out = TextReporter().render(ScanResult(findings=(hostile,)))
        assert "\x1b" not in out
        assert not any(line.startswith("[CRITICAL]") for line in out.splitlines())

    def test_ends_with_a_single_newline(self, result: ScanResult) -> None:
        out = TextReporter().render(result)
        assert out.endswith("\n")
        assert not out.endswith("\n\n")


class TestJsonReporter:
    def test_structure(self, result: ScanResult) -> None:
        payload: dict[str, Any] = json.loads(JsonReporter().render(result))
        assert payload["tool"] == {"name": "devsecops-scanner", "version": __version__}
        assert payload["summary"] == {
            "files_scanned": 12,
            "findings": 4,
            "suppressed": 3,
            "by_severity": {"info": 0, "low": 1, "medium": 1, "high": 0, "critical": 2},
        }
        assert len(payload["findings"]) == 4
        assert payload["issues"][0]["message"] == "oops"

    def test_findings_include_fingerprints(self, result: ScanResult) -> None:
        payload = json.loads(JsonReporter().render(result))
        fingerprints = [f["fingerprint"] for f in payload["findings"]]
        assert fingerprints == [f.fingerprint() for f in result.findings]
        assert all(len(fp) == 32 for fp in fingerprints)

    def test_enums_are_serialised_as_strings(self, result: ScanResult) -> None:
        first = json.loads(JsonReporter().render(result))["findings"][0]
        assert first["severity"] == "critical"
        assert first["kind"] == "sast"
        assert first["location"] == {"path": "app/module.py", "line": 10, "column": 5}

    def test_output_is_ascii_only(self) -> None:
        finding = make_finding(message="ação \u2028 \x1b")
        out = JsonReporter().render(ScanResult(findings=(finding,)))
        assert out.isascii()
        assert json.loads(out)["findings"][0]["message"] == "ação \u2028 \x1b"

    def test_empty_result(self) -> None:
        payload = json.loads(JsonReporter().render(ScanResult()))
        assert payload["findings"] == []
        assert payload["summary"]["findings"] == 0


class TestSarifReporter:
    @pytest.fixture
    def log(self, result: ScanResult) -> dict[str, Any]:
        parsed: dict[str, Any] = json.loads(SarifReporter().render(result))
        return parsed

    def test_top_level(self, log: dict[str, Any]) -> None:
        assert log["version"] == "2.1.0"
        assert log["$schema"].endswith("sarif-2.1.0.json")
        assert len(log["runs"]) == 1
        driver = log["runs"][0]["tool"]["driver"]
        assert driver["name"] == "devsecops-scanner"
        assert driver["version"] == __version__

    def test_rules_are_deduplicated_and_indexed(self, log: dict[str, Any]) -> None:
        run = log["runs"][0]
        rule_ids = [rule["id"] for rule in run["tool"]["driver"]["rules"]]
        assert rule_ids == ["SAST-001", "SAST-004", "SECRET-JWT"]
        indexes = {r["ruleId"]: r["ruleIndex"] for r in run["results"]}
        assert indexes == {"SAST-001": 0, "SAST-004": 1, "SECRET-JWT": 2}
        assert len(run["results"]) == 4

    @pytest.mark.parametrize(
        ("rule_id", "level", "security_severity"),
        [
            ("SAST-001", "error", "9.5"),
            ("SAST-004", "warning", "5.5"),
            ("SECRET-JWT", "note", "3.0"),
        ],
    )
    def test_levels_and_security_severity(
        self, log: dict[str, Any], rule_id: str, level: str, security_severity: str
    ) -> None:
        rule = next(r for r in log["runs"][0]["tool"]["driver"]["rules"] if r["id"] == rule_id)
        assert rule["defaultConfiguration"]["level"] == level
        assert rule["properties"]["security-severity"] == security_severity
        assert "security" in rule["properties"]["tags"]

    def test_cwe_tag_is_zero_padded(self, log: dict[str, Any]) -> None:
        rules = {r["id"]: r for r in log["runs"][0]["tool"]["driver"]["rules"]}
        assert "external/cwe/cwe-095" in rules["SAST-001"]["properties"]["tags"]
        assert "external/cwe/cwe-327" in rules["SAST-004"]["properties"]["tags"]
        assert all("cwe" not in t for t in rules["SECRET-JWT"]["properties"]["tags"])

    def test_result_location(self, log: dict[str, Any]) -> None:
        first = log["runs"][0]["results"][0]
        physical = first["locations"][0]["physicalLocation"]
        assert physical["artifactLocation"] == {"uri": "app/module.py", "uriBaseId": "%SRCROOT%"}
        assert physical["region"] == {
            "startLine": 10,
            "startColumn": 5,
            "snippet": {"text": "code"},
        }
        assert first["message"]["text"] == "A problem was found."
        assert len(first["partialFingerprints"]["dsscan/v1"]) == 32

    def test_uris_are_percent_encoded(self) -> None:
        finding = make_finding(path="my dir/a b#c.py")
        log = json.loads(SarifReporter().render(ScanResult(findings=(finding,))))
        physical = log["runs"][0]["results"][0]["locations"][0]["physicalLocation"]
        assert physical["artifactLocation"]["uri"] == "my%20dir/a%20b%23c.py"

    def test_region_without_column_or_snippet(self) -> None:
        finding = make_finding(column=None, snippet=None)
        log = json.loads(SarifReporter().render(ScanResult(findings=(finding,))))
        region = log["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["region"]
        assert region == {"startLine": 1}

    def test_invocation_reports_notifications(self, log: dict[str, Any]) -> None:
        invocation = log["runs"][0]["invocations"][0]
        assert invocation["executionSuccessful"] is True
        (notification,) = invocation["toolExecutionNotifications"]
        assert notification["level"] == "warning"
        assert notification["message"]["text"] == "(sast) oops"
        physical = notification["locations"][0]["physicalLocation"]
        assert physical["artifactLocation"]["uri"] == "bad.py"

    def test_an_error_issue_marks_the_execution_unsuccessful(self) -> None:
        issue = ScanIssue(level=IssueLevel.ERROR, source="sca", message="crashed")
        log = json.loads(SarifReporter().render(ScanResult(issues=(issue,))))
        invocation = log["runs"][0]["invocations"][0]
        assert invocation["executionSuccessful"] is False
        assert invocation["toolExecutionNotifications"][0]["level"] == "error"
        assert "locations" not in invocation["toolExecutionNotifications"][0]

    def test_empty_result_is_valid(self) -> None:
        log = json.loads(SarifReporter().render(ScanResult()))
        assert log["runs"][0]["results"] == []
        assert log["runs"][0]["tool"]["driver"]["rules"] == []

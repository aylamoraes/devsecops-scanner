"""SARIF 2.1.0 report, the format GitHub code scanning (and most CI dashboards) ingest."""

from __future__ import annotations

import json
from typing import Any, Final
from urllib.parse import quote

from devsecops_scanner import __version__
from devsecops_scanner.core.models import Finding, IssueLevel, ScanIssue, ScanResult, Severity

SARIF_VERSION: Final = "2.1.0"
SARIF_SCHEMA: Final = "https://json.schemastore.org/sarif-2.1.0.json"
FINGERPRINT_KEY: Final = "dsscan/v1"

_LEVEL: Final[dict[Severity, str]] = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
    Severity.INFO: "note",
}
# GitHub ranks code-scanning alerts with this numeric "security-severity" property.
_SECURITY_SEVERITY: Final[dict[Severity, str]] = {
    Severity.CRITICAL: "9.5",
    Severity.HIGH: "8.0",
    Severity.MEDIUM: "5.5",
    Severity.LOW: "3.0",
    Severity.INFO: "0.0",
}


class SarifReporter:
    """Builds a single-run SARIF log. Rules are derived from the findings present."""

    def render(self, result: ScanResult) -> str:
        rule_index: dict[str, int] = {}
        rules: list[dict[str, Any]] = []
        results: list[dict[str, Any]] = []

        for finding in result.findings:
            if finding.rule_id not in rule_index:
                rule_index[finding.rule_id] = len(rules)
                rules.append(_rule(finding))
            results.append(_result(finding, rule_index[finding.rule_id]))

        log: dict[str, Any] = {
            "$schema": SARIF_SCHEMA,
            "version": SARIF_VERSION,
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "devsecops-scanner",
                            "version": __version__,
                            "rules": rules,
                        }
                    },
                    "results": results,
                    "invocations": [
                        {
                            "executionSuccessful": not result.has_errors,
                            "toolExecutionNotifications": [
                                _notification(issue) for issue in result.issues
                            ],
                        }
                    ],
                }
            ],
        }
        return json.dumps(log, indent=2) + "\n"


def _rule(finding: Finding) -> dict[str, Any]:
    tags = ["security"]
    if finding.cwe:
        tags.append(f"external/cwe/cwe-{int(finding.cwe.removeprefix('CWE-')):03d}")
    rule: dict[str, Any] = {
        "id": finding.rule_id,
        "shortDescription": {"text": finding.title},
        "defaultConfiguration": {"level": _LEVEL[finding.severity]},
        "properties": {
            "security-severity": _SECURITY_SEVERITY[finding.severity],
            "tags": tags,
        },
    }
    if finding.remediation:
        rule["help"] = {"text": finding.remediation}
    return rule


def _result(finding: Finding, rule_index: int) -> dict[str, Any]:
    region: dict[str, Any] = {"startLine": finding.location.line}
    if finding.location.column is not None:
        region["startColumn"] = finding.location.column
    if finding.snippet:
        region["snippet"] = {"text": finding.snippet}
    return {
        "ruleId": finding.rule_id,
        "ruleIndex": rule_index,
        "level": _LEVEL[finding.severity],
        "message": {"text": finding.message},
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {
                        "uri": quote(finding.location.path),
                        "uriBaseId": "%SRCROOT%",
                    },
                    "region": region,
                }
            }
        ],
        "partialFingerprints": {FINGERPRINT_KEY: finding.fingerprint()},
    }


def _notification(issue: ScanIssue) -> dict[str, Any]:
    notification: dict[str, Any] = {
        "level": "error" if issue.level is IssueLevel.ERROR else "warning",
        "message": {"text": f"({issue.source}) {issue.message}"},
    }
    if issue.path:
        notification["locations"] = [
            {"physicalLocation": {"artifactLocation": {"uri": quote(issue.path)}}}
        ]
    return notification

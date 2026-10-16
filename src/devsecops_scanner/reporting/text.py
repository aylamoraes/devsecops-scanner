"""Human-readable report for terminals and CI logs."""

from __future__ import annotations

import re
from typing import Final

from devsecops_scanner import __version__
from devsecops_scanner.core.models import Finding, ScanIssue, ScanResult, Severity

# Source lines, paths and messages are untrusted. Replacing control characters stops a
# hostile file from injecting ANSI escape sequences or fake log lines into CI output.
_CONTROL_CHARACTERS: Final = re.compile(r"[\x00-\x1f\x7f-\x9f]")


def sanitize(text: str) -> str:
    """Replace control characters (including newlines and ESC) with ``?``."""
    return _CONTROL_CHARACTERS.sub("?", text)


class TextReporter:
    """Plain-text report, one block per finding, no colors (safe for any log viewer)."""

    def render(self, result: ScanResult) -> str:
        lines = [
            f"devsecops-scanner {__version__}",
            f"Scanned {result.files_scanned} file(s): {len(result.findings)} finding(s), "
            f"{result.suppressed} suppressed.",
            "",
        ]
        for finding in result.findings:
            lines.extend(_format_finding(finding))
            lines.append("")

        counts = result.count_by_severity()
        summary = " | ".join(f"{s.value} {counts[s]}" for s in reversed(list(Severity)))
        lines.append(f"Summary: {summary}")

        if result.issues:
            lines.extend(["", "Scan issues (coverage may be incomplete):"])
            lines.extend(_format_issue(issue) for issue in result.issues)
        return "\n".join(lines) + "\n"


def _format_finding(finding: Finding) -> list[str]:
    location = finding.location
    where = f"{location.path}:{location.line}"
    if location.column is not None:
        where += f":{location.column}"
    block = [
        f"[{finding.severity.value.upper()}] {sanitize(finding.rule_id)} {sanitize(where)}",
        f"  {sanitize(finding.title)}",
        f"  {sanitize(finding.message)}",
    ]
    if finding.snippet:
        block.append(f"  > {sanitize(finding.snippet)}")
    if finding.remediation:
        block.append(f"  Fix: {sanitize(finding.remediation)}")
    if finding.cwe:
        block.append(f"  Ref: {finding.cwe}")
    return block


def _format_issue(issue: ScanIssue) -> str:
    where = f" {sanitize(issue.path)}:" if issue.path else ""
    return f"  [{issue.level.value}] ({issue.source}){where} {sanitize(issue.message)}"

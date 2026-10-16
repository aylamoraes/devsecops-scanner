"""Machine-readable JSON report."""

from __future__ import annotations

import json
from typing import Any

from devsecops_scanner import __version__
from devsecops_scanner.core.models import ScanResult


class JsonReporter:
    """JSON report with a summary, the findings (with fingerprints) and the scan issues.

    Output is ASCII-only (``ensure_ascii``), so control characters and non-ASCII text
    from scanned files are always escaped.
    """

    def render(self, result: ScanResult) -> str:
        counts = result.count_by_severity()
        payload: dict[str, Any] = {
            "tool": {"name": "devsecops-scanner", "version": __version__},
            "summary": {
                "files_scanned": result.files_scanned,
                "findings": len(result.findings),
                "suppressed": result.suppressed,
                "by_severity": {severity.value: count for severity, count in counts.items()},
            },
            "findings": [
                {**finding.model_dump(mode="json"), "fingerprint": finding.fingerprint()}
                for finding in result.findings
            ],
            "issues": [issue.model_dump(mode="json") for issue in result.issues],
        }
        return json.dumps(payload, indent=2) + "\n"

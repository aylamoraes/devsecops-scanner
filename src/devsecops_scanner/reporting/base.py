"""The reporter contract."""

from __future__ import annotations

from typing import Protocol

from devsecops_scanner.core.models import ScanResult


class Reporter(Protocol):
    """Turns a :class:`ScanResult` into text for a human, a script or a code-scanning UI."""

    def render(self, result: ScanResult) -> str:
        """Return the full report as a string."""
        ...

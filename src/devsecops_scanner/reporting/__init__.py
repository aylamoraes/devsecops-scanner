"""Report renderers (Strategy pattern) and the factory that selects one by name."""

from __future__ import annotations

from collections.abc import Callable
from typing import Final

from devsecops_scanner.core.errors import ConfigError
from devsecops_scanner.reporting.base import Reporter
from devsecops_scanner.reporting.json_reporter import JsonReporter
from devsecops_scanner.reporting.sarif import SarifReporter
from devsecops_scanner.reporting.text import TextReporter

_REPORTERS: Final[dict[str, Callable[[], Reporter]]] = {
    "text": TextReporter,
    "json": JsonReporter,
    "sarif": SarifReporter,
}

REPORTER_NAMES: Final[tuple[str, ...]] = tuple(_REPORTERS)


def get_reporter(name: str) -> Reporter:
    """Return a new reporter for ``name`` (``text``, ``json`` or ``sarif``)."""
    factory = _REPORTERS.get(name)
    if factory is None:
        choices = ", ".join(_REPORTERS)
        raise ConfigError(f"unknown report format; choose one of: {choices}")
    return factory()


__all__ = [
    "REPORTER_NAMES",
    "JsonReporter",
    "Reporter",
    "SarifReporter",
    "TextReporter",
    "get_reporter",
]

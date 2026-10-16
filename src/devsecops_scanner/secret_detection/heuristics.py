"""Heuristics that separate real secrets from placeholders, identifiers and references."""

from __future__ import annotations

import math
import re
from collections import Counter
from typing import Final

# Documented example credentials (AWS documentation). They appear in tutorials and tests
# everywhere and are not real secrets.
KNOWN_EXAMPLE_VALUES: Final[frozenset[str]] = frozenset(
    {
        "AKIAIOSFODNN7EXAMPLE",
        "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
    }
)

_PLACEHOLDER_MARKERS: Final[tuple[str, ...]] = (
    "changeme",
    "change_me",
    "change-me",
    "example",
    "placeholder",
    "your_",
    "your-",
    "yourpassword",
    "dummy",
    "sample",
    "redacted",
    "xxxx",
    "todo",
    "fixme",
    "password",
    "insert",
    "replace",
    "${",
    "{{",
    "%(",
    "$(",
    "<",
)
_TEMPLATE_ONLY: Final = re.compile(
    r"^(?:\*+|x+|\.+|-+|#+|\$\{[^}]*\}|<[^>]*>|\{\{.*\}\})$",
    re.IGNORECASE,
)
_IDENTIFIER: Final = re.compile(r"^[a-z][a-z_.-]*$")


def shannon_entropy(value: str) -> float:
    """Shannon entropy in bits per character (0.0 for an empty string)."""
    if not value:
        return 0.0
    total = len(value)
    return -sum((n / total) * math.log2(n / total) for n in Counter(value).values())


def is_placeholder(value: str) -> bool:
    """``True`` for obvious placeholders: ``changeme``, ``${DB_PASSWORD}``, ``<token>``..."""
    lowered = value.casefold()
    if any(marker in lowered for marker in _PLACEHOLDER_MARKERS):
        return True
    return _TEMPLATE_ONLY.match(value) is not None


def looks_like_non_secret(value: str) -> bool:
    """``True`` for URLs, file paths and lowercase identifiers (``get_user_token``)."""
    if "://" in value or value.startswith(("/", "./", "../", "~")):
        return True
    return _IDENTIFIER.match(value) is not None


def redact(secret: str) -> str:
    """Mask a secret for display.

    Values shorter than 16 characters are fully masked. Longer ones keep only the first
    four characters (enough to recognise a provider prefix such as ``AKIA`` or ``ghp_``).
    The number of ``*`` is capped, so the output does not reveal the exact length either.
    """
    if len(secret) < 16:
        return "*" * min(len(secret), 12)
    return secret[:4] + "*" * 12

"""Secret patterns.

Order matters: specific, high-confidence provider patterns come first and the generic
patterns last, so a GitHub token inside ``token = "ghp_..."`` is reported once, as a
GitHub token, and not again as a generic credential.

Every regular expression uses bounded quantifiers, so a hostile input line cannot cause
catastrophic backtracking.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Final

from devsecops_scanner.core.models import Severity


@dataclass(frozen=True, slots=True)
class SecretPattern:
    """A detection rule for one kind of secret."""

    rule_id: str
    title: str
    regex: re.Pattern[str]
    severity: Severity
    secret_group: int = 1
    min_entropy: float | None = None
    skip_placeholders: bool = False
    mask: bool = True  # ``False`` when the matched text is not itself sensitive


_I: Final = re.IGNORECASE

DEFAULT_PATTERNS: Final[tuple[SecretPattern, ...]] = (
    # --- provider-specific, high confidence ---------------------------------------
    SecretPattern(
        "SECRET-AWS-ACCESS-KEY-ID",
        "AWS access key ID",
        re.compile(r"\b((?:AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16})\b"),
        Severity.HIGH,
    ),
    SecretPattern(
        "SECRET-AWS-SECRET-ACCESS-KEY",
        "AWS secret access key",
        re.compile(
            r"\baws_?secret_?(?:access_?)?key\b[\"']?\s*[:=]\s*[\"']?([A-Za-z0-9/+=]{40})"
            r"(?![A-Za-z0-9/+=])",
            _I,
        ),
        Severity.CRITICAL,
        skip_placeholders=True,
    ),
    SecretPattern(
        "SECRET-GITHUB-TOKEN",
        "GitHub token",
        re.compile(r"\b((?:gh[pousr]_[A-Za-z0-9]{36,255}|github_pat_[A-Za-z0-9_]{22,255}))\b"),
        Severity.HIGH,
    ),
    SecretPattern(
        "SECRET-SLACK-TOKEN",
        "Slack token",
        re.compile(r"\b(xox[baprs]-[A-Za-z0-9-]{10,72})"),
        Severity.HIGH,
    ),
    SecretPattern(
        "SECRET-GOOGLE-API-KEY",
        "Google API key",
        re.compile(r"\b(AIza[0-9A-Za-z_-]{35})(?![0-9A-Za-z_-])"),
        Severity.HIGH,
    ),
    SecretPattern(
        "SECRET-STRIPE-LIVE-KEY",
        "Stripe live secret key",
        re.compile(r"\b((?:sk|rk)_live_[0-9A-Za-z]{24,99})\b"),
        Severity.HIGH,
    ),
    SecretPattern(
        "SECRET-PRIVATE-KEY",
        "Private key block",
        re.compile(r"(-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY(?: BLOCK)?-----)"),
        Severity.CRITICAL,
        mask=False,  # the header is public; the sensitive material follows on the next lines
    ),
    SecretPattern(
        "SECRET-JWT",
        "JSON Web Token",
        re.compile(r"\b(eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,})"),
        Severity.MEDIUM,
    ),
    # --- generic, lower confidence: need entropy and placeholder checks -----------
    SecretPattern(
        "SECRET-CONNECTION-STRING",
        "Credentials embedded in a connection string",
        re.compile(
            r"\b([a-z][a-z0-9+.-]{1,20}://[^\s:/@\"']{1,64}:([^\s@/\"']{3,64})@[^\s/\"']+)",
            _I,
        ),
        Severity.HIGH,
        secret_group=2,
        skip_placeholders=True,
    ),
    SecretPattern(
        "SECRET-GENERIC-CREDENTIAL",
        "Hard-coded credential assignment",
        re.compile(
            r"\b[\w.-]{0,40}"
            r"(?:password|passwd|pwd|secret|api[_-]?key|access[_-]?key|auth[_-]?token|token)"
            r"[\w.-]{0,40}[\"']?\s*(?::=|=>|:|=)\s*[\"']([^\"'\s]{8,128})[\"']",
            _I,
        ),
        Severity.MEDIUM,
        min_entropy=3.0,
        skip_placeholders=True,
    ),
    SecretPattern(
        "SECRET-ENV-ASSIGNMENT",
        "Secret assigned in an environment-style file",
        re.compile(
            r"^[ \t]*(?:export[ \t]+)?[A-Z0-9_]*"
            r"(?:PASSWORD|PASSWD|SECRET|TOKEN|API_?KEY|ACCESS_?KEY)[A-Z0-9_]*"
            r"=([A-Za-z0-9/+_.=-]{16,128})[ \t]*$"
        ),
        Severity.MEDIUM,
        min_entropy=3.3,
        skip_placeholders=True,
    ),
)

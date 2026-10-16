"""Test helpers.

Credential-looking fixtures are *built at runtime* and never written as literals. That
keeps the repository clean for secret scanners (this project's own self-scan and
GitHub push protection) while still exercising the real detection patterns.
"""

from __future__ import annotations

import base64
import hashlib
import json
from collections.abc import Iterable
from typing import Any

from devsecops_scanner.core.analyzer import AnalysisItem, Analyzer
from devsecops_scanner.core.filesystem import SourceFile
from devsecops_scanner.core.models import (
    Finding,
    FindingKind,
    Location,
    RuleInfo,
    Severity,
)

# A random-looking 16-character value (distinct characters => high entropy).
HIGH_ENTROPY_VALUE = "".join(["x7Kp2Q", "m9Vz4L", "r8Wd"])


def make_source(text: str, path: str = "app/module.py") -> SourceFile:
    """Build an in-memory source file."""
    return SourceFile.from_text(path, text)


def make_finding(
    *,
    rule_id: str = "SAST-001",
    severity: Severity = Severity.HIGH,
    path: str = "app/module.py",
    line: int = 1,
    column: int | None = 1,
    snippet: str | None = "code",
    match_key: str = "",
    cwe: str | None = "CWE-95",
    kind: FindingKind = FindingKind.SAST,
    message: str = "A problem was found.",
) -> Finding:
    """Build a valid finding with sensible defaults."""
    return Finding(
        rule_id=rule_id,
        kind=kind,
        severity=severity,
        title="Test finding",
        message=message,
        location=Location(path=path, line=line, column=column),
        remediation="Fix it.",
        cwe=cwe,
        snippet=snippet,
        match_key=match_key,
    )


def _hex(seed: str, length: int) -> str:
    return (hashlib.sha256(seed.encode()).hexdigest() * 4)[:length]


def _b64(payload: dict[str, Any]) -> str:
    return base64.urlsafe_b64encode(json.dumps(payload).encode()).rstrip(b"=").decode()


def fake_aws_key_id() -> str:
    return "AKIA" + "Q7W2E9R4T6Y3U8I5"


def fake_aws_secret() -> str:
    return _hex("aws-secret", 40)


def fake_github_token() -> str:
    return "ghp_" + _hex("github", 36)


def fake_slack_token() -> str:
    return "xoxb-" + _hex("slack", 24)


def fake_google_key() -> str:
    return "AIza" + _hex("google", 35)


def fake_stripe_key() -> str:
    return "sk_live_" + _hex("stripe", 32)


def fake_private_key_header() -> str:
    return "-----BEGIN RSA " + "PRIVATE KEY-----"


def fake_jwt() -> str:
    header = _b64({"alg": "HS256", "typ": "JWT"})
    payload = _b64({"sub": "1234567890", "name": "tester"})
    return f"{header}.{payload}.{_hex('signature', 43)}"


class StaticAnalyzer(Analyzer):
    """Test double: accepts ``.py`` files and returns a fixed list of items."""

    def __init__(self, items: Iterable[AnalysisItem], name: str = "static") -> None:
        self._items = list(items)
        self._name = name

    @property
    def name(self) -> str:
        return self._name

    def accepts(self, path: str) -> bool:
        return path.endswith(".py")

    def analyze(self, source: SourceFile) -> Iterable[AnalysisItem]:
        return list(self._items)

    def rules(self) -> tuple[RuleInfo, ...]:
        return ()


class CrashingAnalyzer(Analyzer):
    """Test double: accepts every file and raises ``error`` when asked to analyze it."""

    def __init__(self, error: Exception) -> None:
        self._error = error

    @property
    def name(self) -> str:
        return "crashy"

    def accepts(self, path: str) -> bool:
        return True

    def analyze(self, source: SourceFile) -> Iterable[AnalysisItem]:
        raise self._error

    def rules(self) -> tuple[RuleInfo, ...]:
        return ()

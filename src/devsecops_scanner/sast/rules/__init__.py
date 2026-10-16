"""The built-in SAST rule set."""

from __future__ import annotations

from devsecops_scanner.sast.rules.base import CallRule
from devsecops_scanner.sast.rules.crypto_and_config import (
    DebugModeRule,
    InsecureTempfileRule,
    TlsVerificationRule,
    UnsafeDeserializationRule,
    WeakHashRule,
)
from devsecops_scanner.sast.rules.injection import (
    CodeInjectionRule,
    ShellInjectionRule,
    SqlInjectionRule,
)

DEFAULT_RULES: tuple[CallRule, ...] = (
    CodeInjectionRule(),
    ShellInjectionRule(),
    UnsafeDeserializationRule(),
    WeakHashRule(),
    TlsVerificationRule(),
    SqlInjectionRule(),
    InsecureTempfileRule(),
    DebugModeRule(),
)

__all__ = ["DEFAULT_RULES", "CallRule"]

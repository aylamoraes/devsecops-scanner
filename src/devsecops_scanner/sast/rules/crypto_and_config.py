"""Rules for unsafe deserialization, weak crypto, TLS, temp files and debug mode."""

from __future__ import annotations

import ast
from typing import ClassVar, Final

from devsecops_scanner.core.models import Severity
from devsecops_scanner.sast.rules.base import (
    CallRule,
    first_argument,
    is_constant,
    keyword_value,
)

_UNSAFE_LOADERS: Final = frozenset(
    {
        "pickle.load",
        "pickle.loads",
        "pickle.Unpickler",
        "cPickle.load",
        "cPickle.loads",
        "dill.load",
        "dill.loads",
        "marshal.load",
        "marshal.loads",
        "shelve.open",
        "jsonpickle.decode",
        "yaml.unsafe_load",
        "yaml.unsafe_load_all",
    }
)
_YAML_LOAD: Final = frozenset({"yaml.load", "yaml.load_all"})
_SAFE_YAML_LOADERS: Final = frozenset({"SafeLoader", "CSafeLoader"})
_WEAK_HASHES: Final = frozenset({"md5", "sha1"})


class UnsafeDeserializationRule(CallRule):
    """Deserializers that can execute code while loading untrusted data."""

    rule_id: ClassVar[str] = "SAST-003"
    title: ClassVar[str] = "Unsafe deserialization"
    severity: ClassVar[Severity] = Severity.HIGH
    cwe: ClassVar[str] = "CWE-502"
    remediation: ClassVar[str] = (
        "Do not deserialize untrusted data with pickle/marshal/shelve. Use JSON, or "
        "yaml.safe_load() for YAML."
    )

    def evaluate(self, call: ast.Call, qualified_name: str | None) -> str | None:
        if qualified_name in _UNSAFE_LOADERS:
            return f"{qualified_name}() can execute arbitrary code when loading untrusted data."
        if qualified_name in _YAML_LOAD and not _uses_safe_yaml_loader(call):
            return f"{qualified_name}() is used without SafeLoader."
        return None


def _uses_safe_yaml_loader(call: ast.Call) -> bool:
    loader = keyword_value(call, "Loader")
    if loader is None and len(call.args) >= 2:
        loader = call.args[1]
    if isinstance(loader, ast.Attribute):
        return loader.attr in _SAFE_YAML_LOADERS
    if isinstance(loader, ast.Name):
        return loader.id in _SAFE_YAML_LOADERS
    return False


class WeakHashRule(CallRule):
    """MD5 and SHA-1 are broken for security purposes."""

    rule_id: ClassVar[str] = "SAST-004"
    title: ClassVar[str] = "Weak hash algorithm"
    severity: ClassVar[Severity] = Severity.MEDIUM
    cwe: ClassVar[str] = "CWE-327"
    remediation: ClassVar[str] = (
        "Use SHA-256 or stronger for integrity, and a password KDF (argon2, scrypt, "
        "bcrypt) for passwords. For non-security uses pass usedforsecurity=False."
    )

    def evaluate(self, call: ast.Call, qualified_name: str | None) -> str | None:
        if is_constant(keyword_value(call, "usedforsecurity"), False):
            return None
        if qualified_name is not None and qualified_name.startswith("hashlib."):
            algorithm = qualified_name.split(".", 1)[1]
            if algorithm in _WEAK_HASHES:
                return f"hashlib.{algorithm}() is a weak hash algorithm."
            if algorithm == "new":
                name = first_argument(call)
                if (
                    isinstance(name, ast.Constant)
                    and isinstance(name.value, str)
                    and name.value.lower() in _WEAK_HASHES
                ):
                    return f"hashlib.new() selects the weak algorithm {name.value.lower()}."
        return None


class TlsVerificationRule(CallRule):
    """Certificate validation turned off."""

    rule_id: ClassVar[str] = "SAST-005"
    title: ClassVar[str] = "TLS certificate verification disabled"
    severity: ClassVar[Severity] = Severity.HIGH
    cwe: ClassVar[str] = "CWE-295"
    remediation: ClassVar[str] = (
        "Keep certificate verification on. For private CAs, pass the CA bundle path "
        "(verify='/path/ca.pem') instead of verify=False."
    )

    def evaluate(self, call: ast.Call, qualified_name: str | None) -> str | None:
        if qualified_name == "ssl._create_unverified_context":
            return "ssl._create_unverified_context() disables certificate validation."
        if is_constant(keyword_value(call, "verify"), False):
            return "A call passes verify=False, which disables certificate validation."
        return None


class InsecureTempfileRule(CallRule):
    """``tempfile.mktemp`` is vulnerable to race conditions."""

    rule_id: ClassVar[str] = "SAST-007"
    title: ClassVar[str] = "Insecure temporary file"
    severity: ClassVar[Severity] = Severity.MEDIUM
    cwe: ClassVar[str] = "CWE-377"
    remediation: ClassVar[str] = (
        "Use tempfile.mkstemp(), tempfile.NamedTemporaryFile() or tempfile.TemporaryDirectory()."
    )

    def evaluate(self, call: ast.Call, qualified_name: str | None) -> str | None:
        if qualified_name == "tempfile.mktemp":
            return "tempfile.mktemp() returns a name without creating the file (race condition)."
        return None


class DebugModeRule(CallRule):
    """Web frameworks started in debug mode expose an interactive debugger."""

    rule_id: ClassVar[str] = "SAST-008"
    title: ClassVar[str] = "Debug mode enabled"
    severity: ClassVar[Severity] = Severity.MEDIUM
    cwe: ClassVar[str] = "CWE-489"
    remediation: ClassVar[str] = (
        "Never enable debug mode in production. Read it from the environment and default to off."
    )

    def evaluate(self, call: ast.Call, qualified_name: str | None) -> str | None:
        is_run = isinstance(call.func, ast.Attribute) and call.func.attr == "run"
        if is_run and is_constant(keyword_value(call, "debug"), True):
            return "An application server is started with debug=True."
        return None

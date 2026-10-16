"""Injection rules: code, OS command and SQL."""

from __future__ import annotations

import ast
import re
from typing import ClassVar, Final

from devsecops_scanner.core.models import Severity
from devsecops_scanner.sast.rules.base import (
    CallRule,
    first_argument,
    is_constant,
    is_string_literal,
    keyword_value,
)

_SUBPROCESS_FUNCTIONS: Final = frozenset(
    {
        "subprocess.run",
        "subprocess.call",
        "subprocess.check_call",
        "subprocess.check_output",
        "subprocess.Popen",
    }
)
# These always run through a shell, with no way to opt out.
_ALWAYS_SHELL: Final = frozenset(
    {"os.system", "os.popen", "subprocess.getoutput", "subprocess.getstatusoutput"}
)
_DYNAMIC_EXECUTION: Final = frozenset({"eval", "exec", "builtins.eval", "builtins.exec"})
_SQL_VERB: Final = re.compile(
    r"\b(select|insert|update|delete|drop|create|alter|replace|merge)\b",
    re.IGNORECASE,
)
_EXECUTE_METHODS: Final = frozenset({"execute", "executemany", "executescript"})


class CodeInjectionRule(CallRule):
    """``eval`` and ``exec`` on non-literal input."""

    rule_id: ClassVar[str] = "SAST-001"
    title: ClassVar[str] = "Dynamic code execution"
    severity: ClassVar[Severity] = Severity.HIGH
    cwe: ClassVar[str] = "CWE-95"
    remediation: ClassVar[str] = (
        "Avoid eval()/exec(). Use ast.literal_eval() for literals, or a dispatch table "
        "for a fixed set of operations."
    )

    def evaluate(self, call: ast.Call, qualified_name: str | None) -> str | None:
        if qualified_name is None or qualified_name not in _DYNAMIC_EXECUTION:
            return None
        if is_string_literal(first_argument(call)):
            return None  # a constant string is not attacker-controlled
        return f"{qualified_name.split('.')[-1]}() is called with a non-constant argument."


class ShellInjectionRule(CallRule):
    """OS commands built from non-constant strings and run through a shell."""

    rule_id: ClassVar[str] = "SAST-002"
    title: ClassVar[str] = "OS command injection risk"
    severity: ClassVar[Severity] = Severity.HIGH
    cwe: ClassVar[str] = "CWE-78"
    remediation: ClassVar[str] = (
        "Pass the command as a list of arguments without shell=True, for example "
        "subprocess.run(['git', 'log', ref], check=True). Validate any user-controlled value."
    )

    def evaluate(self, call: ast.Call, qualified_name: str | None) -> str | None:
        if qualified_name is None or is_string_literal(first_argument(call)):
            return None
        if qualified_name in _ALWAYS_SHELL:
            return f"{qualified_name}() runs a non-constant command through a shell."
        if qualified_name in _SUBPROCESS_FUNCTIONS and is_constant(
            keyword_value(call, "shell"), True
        ):
            return f"{qualified_name}() uses shell=True with a non-constant command."
        return None


class SqlInjectionRule(CallRule):
    """SQL statements assembled with string formatting instead of bound parameters."""

    rule_id: ClassVar[str] = "SAST-006"
    title: ClassVar[str] = "SQL injection risk"
    severity: ClassVar[Severity] = Severity.HIGH
    cwe: ClassVar[str] = "CWE-89"
    remediation: ClassVar[str] = (
        "Use parameterized queries: cursor.execute('SELECT ... WHERE id = %s', (user_id,)). "
        "Never build SQL with f-strings, '%', '+' or str.format()."
    )

    def evaluate(self, call: ast.Call, qualified_name: str | None) -> str | None:
        func = call.func
        if not isinstance(func, ast.Attribute) or func.attr not in _EXECUTE_METHODS:
            return None
        statement = first_argument(call)
        if statement is None or not _builds_dynamic_string(statement):
            return None
        # Cheap guard against unrelated ``.execute()`` methods: the literal fragments
        # must look like SQL.
        if not _SQL_VERB.search(_literal_text(statement)):
            return None
        return f".{func.attr}() receives a SQL statement built with string formatting."


def _builds_dynamic_string(expression: ast.expr) -> bool:
    """``True`` for f-strings, ``%``/``+`` concatenation and ``.format()`` with dynamic parts."""
    if isinstance(expression, ast.JoinedStr):
        return any(isinstance(part, ast.FormattedValue) for part in expression.values)
    if isinstance(expression, ast.BinOp) and isinstance(expression.op, ast.Add | ast.Mod):
        has_string = any(
            isinstance(node, ast.Constant) and isinstance(node.value, str)
            for node in ast.walk(expression)
        )
        return has_string and not _all_constant(expression)
    if (
        isinstance(expression, ast.Call)
        and isinstance(expression.func, ast.Attribute)
        and expression.func.attr == "format"
        and is_string_literal(expression.func.value)
    ):
        return bool(expression.args or expression.keywords)
    return False


def _all_constant(expression: ast.expr) -> bool:
    dynamic = (ast.Name, ast.Attribute, ast.Call, ast.Subscript, ast.FormattedValue)
    return not any(isinstance(node, dynamic) for node in ast.walk(expression))


def _literal_text(expression: ast.expr) -> str:
    """Concatenate the string-literal fragments found inside ``expression``."""
    return " ".join(
        node.value
        for node in ast.walk(expression)
        if isinstance(node, ast.Constant) and isinstance(node.value, str)
    )

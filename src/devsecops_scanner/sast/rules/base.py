"""Rule abstraction and helpers shared by every SAST rule."""

from __future__ import annotations

import ast
from abc import ABC, abstractmethod
from typing import ClassVar

from devsecops_scanner.core.models import Severity


class CallRule(ABC):
    """A rule that inspects a single function call.

    To add a rule: subclass this, fill in the class attributes, implement
    :meth:`evaluate`, and append an instance to ``DEFAULT_RULES``. The analyzer does not
    change (Open/Closed).
    """

    rule_id: ClassVar[str]
    title: ClassVar[str]
    severity: ClassVar[Severity]
    cwe: ClassVar[str]
    remediation: ClassVar[str]

    @abstractmethod
    def evaluate(self, call: ast.Call, qualified_name: str | None) -> str | None:
        """Return a short explanation when ``call`` is insecure, otherwise ``None``.

        ``qualified_name`` is the import-resolved dotted name of the callee, when the
        callee is a plain name or attribute chain. The explanation must not repeat
        source code verbatim.
        """


def keyword_value(call: ast.Call, name: str) -> ast.expr | None:
    """Return the value passed as keyword ``name``, or ``None`` when absent."""
    for keyword in call.keywords:
        if keyword.arg == name:
            return keyword.value
    return None


def is_constant(expression: ast.expr | None, value: object) -> bool:
    """``True`` when ``expression`` is the literal ``value`` (compared by identity for bools)."""
    return isinstance(expression, ast.Constant) and expression.value is value


def is_string_literal(expression: ast.expr | None) -> bool:
    """``True`` when ``expression`` is a plain string literal."""
    return isinstance(expression, ast.Constant) and isinstance(expression.value, str)


def first_argument(call: ast.Call) -> ast.expr | None:
    """Return the first positional argument, or ``None``."""
    return call.args[0] if call.args else None

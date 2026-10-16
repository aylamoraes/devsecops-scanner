"""Resolve names in call expressions to fully qualified names.

Without this, a rule for ``subprocess.run`` would be bypassed by ``import subprocess as sp``
or ``from subprocess import run``. The resolution is deliberately simple and
scope-insensitive: every import in the file is collected first, then names are looked up.
Aliases created by assignment (``p = pickle``) are not followed.
"""

from __future__ import annotations

import ast


class ImportMap:
    """Maps a locally bound name to the dotted path it was imported from."""

    def __init__(self) -> None:
        self._bindings: dict[str, str] = {}

    @classmethod
    def from_tree(cls, tree: ast.AST) -> ImportMap:
        """Collect every ``import`` and ``from ... import`` in ``tree``."""
        mapping = cls()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    if alias.asname:
                        mapping._bindings[alias.asname] = alias.name
                    else:
                        # ``import os.path`` binds only the top-level name ``os``.
                        top = alias.name.split(".")[0]
                        mapping._bindings[top] = top
            elif isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
                for alias in node.names:
                    if alias.name == "*":
                        continue
                    mapping._bindings[alias.asname or alias.name] = f"{node.module}.{alias.name}"
        return mapping

    def resolve(self, expression: ast.expr) -> str | None:
        """Return the qualified dotted name of ``expression`` or ``None``.

        ``None`` means the expression is not a plain (possibly dotted) name, for example
        a call result (``get().run``) or a subscript.
        """
        parts: list[str] = []
        node = expression
        while isinstance(node, ast.Attribute):
            parts.append(node.attr)
            node = node.value
        if not isinstance(node, ast.Name):
            return None
        parts.append(self._bindings.get(node.id, node.id))
        return ".".join(reversed(parts))

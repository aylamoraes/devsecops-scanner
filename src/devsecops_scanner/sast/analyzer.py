"""SAST analyzer: parses Python files and applies call rules."""

from __future__ import annotations

import ast
from collections.abc import Iterable, Iterator, Sequence

from devsecops_scanner.core.analyzer import AnalysisItem, Analyzer
from devsecops_scanner.core.errors import FileAnalysisError
from devsecops_scanner.core.filesystem import SourceFile
from devsecops_scanner.core.models import Finding, FindingKind, Location, RuleInfo
from devsecops_scanner.sast.imports import ImportMap
from devsecops_scanner.sast.rules import DEFAULT_RULES, CallRule

_SNIPPET_LIMIT = 160


class SastAnalyzer(Analyzer):
    """Applies :class:`CallRule` objects to every call expression in a Python file.

    The source is only parsed, never imported or executed.
    """

    def __init__(self, rules: Sequence[CallRule] = DEFAULT_RULES) -> None:
        self._rules = tuple(rules)

    @property
    def name(self) -> str:
        return "sast"

    def accepts(self, path: str) -> bool:
        return path.endswith(".py")

    def rules(self) -> tuple[RuleInfo, ...]:
        return tuple(
            RuleInfo(
                rule_id=rule.rule_id,
                kind=FindingKind.SAST,
                severity=rule.severity,
                title=rule.title,
                cwe=rule.cwe,
            )
            for rule in self._rules
        )

    def analyze(self, source: SourceFile) -> Iterable[AnalysisItem]:
        tree = _parse(source)
        imports = ImportMap.from_tree(tree)
        return list(self._scan(tree, imports, source))

    def _scan(self, tree: ast.AST, imports: ImportMap, source: SourceFile) -> Iterator[Finding]:
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            qualified_name = imports.resolve(node.func)
            for rule in self._rules:
                detail = rule.evaluate(node, qualified_name)
                if detail is not None:
                    yield _to_finding(rule, node, detail, source)


def _parse(source: SourceFile) -> ast.Module:
    try:
        return ast.parse(source.text, filename=source.path)
    except SyntaxError as exc:
        raise FileAnalysisError(
            f"syntax error near line {exc.lineno or '?'}; file not analyzed"
        ) from exc
    except (ValueError, RecursionError) as exc:
        raise FileAnalysisError("file could not be parsed; file not analyzed") from exc


def _to_finding(rule: CallRule, node: ast.Call, detail: str, source: SourceFile) -> Finding:
    snippet = source.line_text(node.lineno).strip()[:_SNIPPET_LIMIT] or None
    return Finding(
        rule_id=rule.rule_id,
        kind=FindingKind.SAST,
        severity=rule.severity,
        title=rule.title,
        message=detail,
        location=Location(path=source.path, line=node.lineno, column=node.col_offset + 1),
        remediation=rule.remediation,
        cwe=rule.cwe,
        snippet=snippet,
        match_key=str(node.col_offset + 1),
    )

"""Unit tests for inline suppression directives."""

from __future__ import annotations

import pytest

from devsecops_scanner.core.suppression import Directive, is_suppressed, parse_directive
from tests.helpers import make_finding, make_source


class TestParseDirective:
    @pytest.mark.parametrize(
        "line",
        [
            "x = 1  # dsscan: ignore",
            "x = 1  #dsscan:ignore",
            "x = 1  # DSSCAN: IGNORE",
            "int x; // dsscan: ignore",
            "SELECT 1; -- dsscan: ignore",
            "/* dsscan: ignore */",
            "<!-- dsscan: ignore -->",
        ],
    )
    def test_recognises_comment_styles(self, line: str) -> None:
        directive = parse_directive(line)
        assert directive == Directive(rule_ids=frozenset())

    @pytest.mark.parametrize(
        "line", ["x = 1", "# just a comment", "# dsscan: allow", "dsscan: ignore", "x = 'ignore'"]
    )
    def test_ignores_other_lines(self, line: str) -> None:
        assert parse_directive(line) is None

    def test_parses_rule_list(self) -> None:
        directive = parse_directive("x  # dsscan: ignore[SAST-001, Secret-JWT ,]")
        assert directive == Directive(rule_ids=frozenset({"sast-001", "secret-jwt"}))

    def test_empty_brackets_never_become_a_wildcard(self) -> None:
        directive = parse_directive("x  # dsscan: ignore[]")
        assert directive is not None
        assert directive.covers("SAST-001") is False


class TestDirectiveCovers:
    def test_wildcard_covers_everything(self) -> None:
        assert Directive(rule_ids=frozenset()).covers("ANYTHING") is True

    def test_is_case_insensitive(self) -> None:
        assert Directive(rule_ids=frozenset({"sast-001"})).covers("SAST-001") is True

    def test_other_rule_is_not_covered(self) -> None:
        assert Directive(rule_ids=frozenset({"sast-001"})).covers("SAST-002") is False


class TestIsSuppressed:
    def test_same_line(self) -> None:
        source = make_source("a = 1\nb = eval(x)  # dsscan: ignore\n")
        assert is_suppressed(make_finding(line=2), source) is True

    def test_line_above_when_it_is_only_a_comment(self) -> None:
        source = make_source("# dsscan: ignore[SAST-001]\nb = eval(x)\n")
        assert is_suppressed(make_finding(line=2), source) is True

    def test_line_above_with_code_does_not_count(self) -> None:
        source = make_source("a = 1  # dsscan: ignore\nb = eval(x)\n")
        assert is_suppressed(make_finding(line=2), source) is False

    def test_only_the_named_rule_is_suppressed(self) -> None:
        source = make_source("b = eval(x)  # dsscan: ignore[SAST-002]\n")
        assert is_suppressed(make_finding(rule_id="SAST-001", line=1), source) is False
        assert is_suppressed(make_finding(rule_id="SAST-002", line=1), source) is True

    def test_two_lines_above_does_not_count(self) -> None:
        source = make_source("# dsscan: ignore\n\nb = eval(x)\n")
        assert is_suppressed(make_finding(line=3), source) is False

    def test_first_line_has_no_line_above(self) -> None:
        source = make_source("b = eval(x)\n")
        assert is_suppressed(make_finding(line=1), source) is False

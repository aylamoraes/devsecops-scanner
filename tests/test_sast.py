"""Unit tests for the SAST engine: import resolution, every rule, and the analyzer."""

from __future__ import annotations

import ast

import pytest

from devsecops_scanner.core.errors import FileAnalysisError
from devsecops_scanner.core.models import Finding, FindingKind, Severity
from devsecops_scanner.sast import SastAnalyzer
from devsecops_scanner.sast.imports import ImportMap
from devsecops_scanner.sast.rules import DEFAULT_RULES
from tests.helpers import make_source


def scan(code: str, path: str = "app.py") -> list[Finding]:
    items = SastAnalyzer().analyze(make_source(code, path))
    return [item for item in items if isinstance(item, Finding)]


def rule_ids(code: str) -> list[str]:
    return [finding.rule_id for finding in scan(code)]


def resolve(code: str) -> str | None:
    tree = ast.parse(code)
    call = next(node for node in ast.walk(tree) if isinstance(node, ast.Call))
    return ImportMap.from_tree(tree).resolve(call.func)


class TestImportMap:
    @pytest.mark.parametrize(
        ("code", "expected"),
        [
            ("import os\nos.system(c)", "os.system"),
            ("import os.path\nos.path.join(a)", "os.path.join"),
            ("import subprocess as sp\nsp.run(c)", "subprocess.run"),
            ("from subprocess import run\nrun(c)", "subprocess.run"),
            ("from subprocess import run as r\nr(c)", "subprocess.run"),
            ("import a.b as c\nc.f()", "a.b.f"),
            ("unknown.attr.call()", "unknown.attr.call"),
            ("eval(x)", "eval"),
        ],
    )
    def test_resolves_names(self, code: str, expected: str) -> None:
        assert resolve(code) == expected

    @pytest.mark.parametrize(
        "code",
        ["get().run()", "items[0].run()", "(lambda: 1)()"],
    )
    def test_non_name_callees_resolve_to_none(self, code: str) -> None:
        assert resolve(code) is None

    def test_relative_and_star_imports_are_ignored(self) -> None:
        code = "from . import tools\nfrom os import *\ntools.run()"
        assert resolve(code) == "tools.run"


class TestCodeInjection:
    @pytest.mark.parametrize(
        "code",
        ["eval(user)", "exec(code)", "eval(f'{a}+1')", "import builtins\nbuiltins.eval(x)"],
    )
    def test_flags_dynamic_execution(self, code: str) -> None:
        assert rule_ids(code) == ["SAST-001"]

    @pytest.mark.parametrize(
        "code",
        ["eval('1 + 1')", "exec('pass')", "import ast\nast.literal_eval(x)", "model.eval()"],
    )
    def test_ignores_safe_forms(self, code: str) -> None:
        assert rule_ids(code) == []


class TestShellInjection:
    @pytest.mark.parametrize(
        "code",
        [
            "import os\nos.system(cmd)",
            "import os\nos.popen(cmd)",
            "import subprocess\nsubprocess.run(cmd, shell=True)",
            "import subprocess\nsubprocess.Popen(cmd, shell=True)",
            "import subprocess as sp\nsp.check_output(cmd, shell=True)",
            "from subprocess import run\nrun(cmd, shell=True)",
            "from os import system\nsystem(cmd)",
            "import subprocess\nsubprocess.getoutput(cmd)",
        ],
    )
    def test_flags_dynamic_shell_commands(self, code: str) -> None:
        assert rule_ids(code) == ["SAST-002"]

    @pytest.mark.parametrize(
        "code",
        [
            "import os\nos.system('ls -l')",
            "import subprocess\nsubprocess.run(['ls', arg])",
            "import subprocess\nsubprocess.run(cmd)",
            "import subprocess\nsubprocess.run('ls -l', shell=True)",
            "import subprocess\nsubprocess.run(cmd, shell=False)",
        ],
    )
    def test_ignores_safe_forms(self, code: str) -> None:
        assert rule_ids(code) == []


class TestUnsafeDeserialization:
    @pytest.mark.parametrize(
        "code",
        [
            "import pickle\npickle.loads(data)",
            "import pickle as pk\npk.load(fh)",
            "from pickle import loads\nloads(data)",
            "import marshal\nmarshal.loads(b)",
            "import shelve\nshelve.open(path)",
            "import yaml\nyaml.load(data)",
            "import yaml\nyaml.load(data, Loader=yaml.FullLoader)",
            "import yaml\nyaml.unsafe_load(data)",
        ],
    )
    def test_flags_unsafe_loaders(self, code: str) -> None:
        assert rule_ids(code) == ["SAST-003"]

    @pytest.mark.parametrize(
        "code",
        [
            "import yaml\nyaml.safe_load(data)",
            "import yaml\nyaml.load(data, Loader=yaml.SafeLoader)",
            "import yaml\nyaml.load(data, yaml.SafeLoader)",
            "import yaml\nfrom yaml import SafeLoader\nyaml.load(data, SafeLoader)",
            "import json\njson.loads(data)",
        ],
    )
    def test_ignores_safe_forms(self, code: str) -> None:
        assert rule_ids(code) == []


class TestWeakHash:
    @pytest.mark.parametrize(
        "code",
        [
            "import hashlib\nhashlib.md5(b'x')",
            "import hashlib\nhashlib.sha1(b'x')",
            "import hashlib as h\nh.md5(b'x')",
            "from hashlib import md5\nmd5(b'x')",
            "import hashlib\nhashlib.new('md5')",
            "import hashlib\nhashlib.new('MD5')",
            "import hashlib\nhashlib.new('sha1', b'x')",
        ],
    )
    def test_flags_weak_algorithms(self, code: str) -> None:
        assert rule_ids(code) == ["SAST-004"]

    @pytest.mark.parametrize(
        "code",
        [
            "import hashlib\nhashlib.sha256(b'x')",
            "import hashlib\nhashlib.new('sha256')",
            "import hashlib\nhashlib.md5(b'x', usedforsecurity=False)",
            "import hashlib\nhashlib.blake2b(b'x')",
        ],
    )
    def test_ignores_strong_or_explicitly_non_security_uses(self, code: str) -> None:
        assert rule_ids(code) == []


class TestTlsVerification:
    @pytest.mark.parametrize(
        "code",
        [
            "import requests\nrequests.get(url, verify=False)",
            "import httpx\nhttpx.Client(verify=False)",
            "import ssl\nssl._create_unverified_context()",
        ],
    )
    def test_flags_disabled_verification(self, code: str) -> None:
        assert rule_ids(code) == ["SAST-005"]

    @pytest.mark.parametrize(
        "code",
        [
            "import requests\nrequests.get(url, verify=True)",
            "import requests\nrequests.get(url, verify='/etc/ssl/ca.pem')",
            "import requests\nrequests.get(url)",
        ],
    )
    def test_ignores_safe_forms(self, code: str) -> None:
        assert rule_ids(code) == []


class TestSqlInjection:
    @pytest.mark.parametrize(
        "code",
        [
            'cur.execute(f"SELECT * FROM users WHERE id = {uid}")',
            'cur.execute("SELECT * FROM users WHERE name = \'" + name + "\'")',
            'cur.execute("SELECT * FROM users WHERE id = %s" % uid)',
            'cur.execute("SELECT * FROM users WHERE id = {}".format(uid))',
            'cur.executemany(f"INSERT INTO t VALUES ({v})", rows)',
            'conn.execute(f"DELETE FROM t WHERE id = {i}")',
        ],
    )
    def test_flags_string_built_queries(self, code: str) -> None:
        assert rule_ids(code) == ["SAST-006"]

    @pytest.mark.parametrize(
        "code",
        [
            'cur.execute("SELECT * FROM users WHERE id = %s", (uid,))',
            'cur.execute("SELECT * FROM users")',
            'cur.execute("SELECT " + "1")',
            'task.execute(f"deploy {env}")',
            "cur.execute(query)",
            "cur.execute()",
        ],
    )
    def test_ignores_parameterized_or_non_sql(self, code: str) -> None:
        assert rule_ids(code) == []


class TestTempfileAndDebug:
    def test_mktemp(self) -> None:
        assert rule_ids("import tempfile\ntempfile.mktemp()") == ["SAST-007"]

    def test_mkstemp_is_fine(self) -> None:
        assert rule_ids("import tempfile\ntempfile.mkstemp()") == []

    def test_debug_true(self) -> None:
        assert rule_ids("app.run(debug=True)") == ["SAST-008"]

    @pytest.mark.parametrize("code", ["app.run(debug=False)", "app.run()", "app.run(port=1)"])
    def test_debug_off_is_fine(self, code: str) -> None:
        assert rule_ids(code) == []


class TestAnalyzer:
    def test_only_python_files_are_accepted(self) -> None:
        analyzer = SastAnalyzer()
        assert analyzer.accepts("a/b.py") is True
        assert analyzer.accepts("a/b.txt") is False
        assert analyzer.accepts("a/b.pyc") is False
        assert analyzer.name == "sast"

    def test_finding_carries_location_and_metadata(self) -> None:
        code = "import os\n\nvalue = os.system(cmd)\n"
        (finding,) = scan(code, "pkg/run.py")
        assert finding.kind is FindingKind.SAST
        assert finding.severity is Severity.HIGH
        assert (finding.location.path, finding.location.line) == ("pkg/run.py", 3)
        assert finding.location.column == 9
        assert finding.cwe == "CWE-78"
        assert finding.snippet == "value = os.system(cmd)"
        assert finding.remediation

    def test_nested_and_chained_calls_are_found(self) -> None:
        code = "import os\nprint(os.system(cmd))\nfn(lambda: eval(x))\n"
        assert sorted(rule_ids(code)) == ["SAST-001", "SAST-002"]

    def test_two_calls_on_one_line_get_distinct_fingerprints(self) -> None:
        findings = scan("a = eval(x); b = eval(y)\n")
        assert len(findings) == 2
        assert len({f.fingerprint() for f in findings}) == 2

    def test_clean_code_has_no_findings(self) -> None:
        assert scan("def add(a: int, b: int) -> int:\n    return a + b\n") == []

    def test_does_not_execute_the_code_it_analyzes(self) -> None:
        # If this were executed, the SystemExit would abort the test run.
        assert scan("raise SystemExit(99)\nimport os\nos.system(x)\n") != []

    def test_syntax_error_raises_a_file_error_with_the_line(self) -> None:
        with pytest.raises(FileAnalysisError, match="syntax error near line 2"):
            SastAnalyzer().analyze(make_source("x = 1\ndef broken(:\n"))

    def test_syntax_error_message_does_not_echo_source(self) -> None:
        marker = "SECRET_MARKER_123"
        with pytest.raises(FileAnalysisError) as info:
            SastAnalyzer().analyze(make_source(f"{marker} = = 1\n"))
        assert marker not in str(info.value)

    def test_pathologically_nested_source_is_a_file_error_not_a_crash(self) -> None:
        deep = "x = " + "(" * 5000 + "1" + ")" * 5000
        with pytest.raises(FileAnalysisError):
            SastAnalyzer().analyze(make_source(deep))

    def test_null_byte_is_a_file_error(self) -> None:
        with pytest.raises(FileAnalysisError):
            SastAnalyzer().analyze(make_source("x = 1\x00\n"))


class TestRuleCatalogue:
    def test_rule_ids_are_unique_and_documented(self) -> None:
        ids = [rule.rule_id for rule in DEFAULT_RULES]
        assert len(ids) == len(set(ids))
        assert ids == sorted(ids)

    def test_every_rule_has_complete_metadata(self) -> None:
        for rule in DEFAULT_RULES:
            assert rule.rule_id.startswith("SAST-")
            assert rule.title
            assert rule.remediation
            assert rule.cwe.startswith("CWE-")

    def test_rules_listing_matches_the_catalogue(self) -> None:
        listed = SastAnalyzer().rules()
        assert [r.rule_id for r in listed] == [r.rule_id for r in DEFAULT_RULES]
        assert all(r.kind is FindingKind.SAST for r in listed)

    def test_custom_rule_set_is_respected(self) -> None:
        from devsecops_scanner.sast.rules.injection import CodeInjectionRule

        analyzer = SastAnalyzer(rules=[CodeInjectionRule()])
        items = analyzer.analyze(make_source("import os\nos.system(c)\neval(x)\n"))
        assert [i.rule_id for i in items if isinstance(i, Finding)] == ["SAST-001"]

"""Integration tests for the command-line interface (exit codes, options, output)."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from devsecops_scanner import __version__
from devsecops_scanner.cli import EXIT_ERROR, EXIT_FINDINGS, EXIT_OK, main
from devsecops_scanner.core.engine import ScanEngine
from tests.conftest import WriteTree
from tests.helpers import CrashingAnalyzer, fake_github_token

VULNERABLE = {"app.py": "value = eval(user_input)\n"}  # SAST-001, severity HIGH


def run_json(argv: list[str], capsys: pytest.CaptureFixture[str]) -> tuple[int, dict[str, Any]]:
    code = main([*argv, "--format", "json"])
    payload: dict[str, Any] = json.loads(capsys.readouterr().out)
    return code, payload


class TestExitCodes:
    def test_clean_scan_exits_zero(
        self, write_tree: WriteTree, capsys: pytest.CaptureFixture[str]
    ) -> None:
        root = write_tree({"ok.py": "x = 1\n"})
        assert main(["scan", str(root)]) == EXIT_OK
        assert "0 finding(s)" in capsys.readouterr().out

    def test_finding_at_threshold_exits_one(self, write_tree: WriteTree) -> None:
        assert main(["scan", str(write_tree(VULNERABLE))]) == EXIT_FINDINGS

    def test_finding_below_threshold_exits_zero(self, write_tree: WriteTree) -> None:
        assert main(["scan", str(write_tree(VULNERABLE)), "--fail-on", "critical"]) == EXIT_OK

    def test_fail_on_none_never_fails(self, write_tree: WriteTree) -> None:
        assert main(["scan", str(write_tree(VULNERABLE)), "--fail-on", "none"]) == EXIT_OK

    def test_fail_on_low_fails_on_medium_findings(self, write_tree: WriteTree) -> None:
        root = write_tree({"a.py": "import hashlib\nhashlib.md5(b'x')\n"})  # MEDIUM
        assert main(["scan", str(root)]) == EXIT_OK
        assert main(["scan", str(root), "--fail-on", "low"]) == EXIT_FINDINGS

    def test_warnings_alone_do_not_fail_the_build(
        self, write_tree: WriteTree, capsys: pytest.CaptureFixture[str]
    ) -> None:
        root = write_tree({"broken.py": "def (:\n"})
        assert main(["scan", str(root)]) == EXIT_OK
        out = capsys.readouterr().out
        assert "Scan issues" in out
        assert "broken.py" in out

    def test_analyzer_crash_exits_two_even_without_findings(
        self,
        write_tree: WriteTree,
        monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        engine = ScanEngine([CrashingAnalyzer(RuntimeError("boom"))])
        monkeypatch.setattr("devsecops_scanner.cli.build_engine", lambda config: engine)
        assert main(["scan", str(write_tree({"a.py": "x = 1\n"}))]) == EXIT_ERROR
        assert "analyzer crashed" in capsys.readouterr().out

    def test_missing_path_exits_two(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        assert main(["scan", str(tmp_path / "nope")]) == EXIT_ERROR
        assert "error: scan path does not exist" in capsys.readouterr().err

    def test_scanning_a_single_file(self, write_tree: WriteTree) -> None:
        root = write_tree({**VULNERABLE, "clean.py": "x = 1\n"})
        assert main(["scan", str(root / "clean.py")]) == EXIT_OK
        assert main(["scan", str(root / "app.py")]) == EXIT_FINDINGS


class TestArgparse:
    def test_version(self, capsys: pytest.CaptureFixture[str]) -> None:
        with pytest.raises(SystemExit) as info:
            main(["--version"])
        assert info.value.code == 0
        assert f"dsscan {__version__}" in capsys.readouterr().out

    def test_a_command_is_required(self) -> None:
        with pytest.raises(SystemExit) as info:
            main([])
        assert info.value.code == 2

    @pytest.mark.parametrize(
        "extra",
        [["--fail-on", "urgent"], ["--format", "xml"], ["--only", "nonsense"]],
    )
    def test_invalid_choices_are_rejected(self, extra: list[str], tmp_path: Path) -> None:
        with pytest.raises(SystemExit) as info:
            main(["scan", str(tmp_path), *extra])
        assert info.value.code == 2

    def test_path_defaults_to_the_current_directory(
        self, write_tree: WriteTree, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.chdir(write_tree(VULNERABLE))
        assert main(["scan"]) == EXIT_FINDINGS


class TestFormats:
    def test_json_to_stdout(
        self, write_tree: WriteTree, capsys: pytest.CaptureFixture[str]
    ) -> None:
        code, payload = run_json(["scan", str(write_tree(VULNERABLE))], capsys)
        assert code == EXIT_FINDINGS
        assert [f["rule_id"] for f in payload["findings"]] == ["SAST-001"]
        assert payload["summary"]["files_scanned"] == 1

    def test_sarif_to_a_file(
        self,
        write_tree: WriteTree,
        tmp_path_factory: pytest.TempPathFactory,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        out_dir = tmp_path_factory.mktemp("out")
        target = out_dir / "report.sarif"
        code = main(["scan", str(write_tree(VULNERABLE)), "-f", "sarif", "-o", str(target)])
        captured = capsys.readouterr()
        assert code == EXIT_FINDINGS
        assert captured.out == ""
        assert "report written to" in captured.err
        log = json.loads(target.read_text(encoding="utf-8"))
        assert log["version"] == "2.1.0"
        assert log["runs"][0]["results"][0]["ruleId"] == "SAST-001"

    def test_unwritable_output_exits_two(
        self, write_tree: WriteTree, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        missing_dir = tmp_path / "no" / "such" / "dir" / "r.json"
        code = main(["scan", str(write_tree(VULNERABLE)), "-f", "json", "-o", str(missing_dir)])
        assert code == EXIT_ERROR
        assert "report could not be written" in capsys.readouterr().err


class TestOptions:
    def test_only_selects_analyzers(
        self, write_tree: WriteTree, capsys: pytest.CaptureFixture[str]
    ) -> None:
        root = write_tree({"a.py": f'x = eval(y)\nk = "{fake_github_token()}"\n'})
        _, everything = run_json(["scan", str(root)], capsys)
        assert {f["kind"] for f in everything["findings"]} == {"sast", "secret"}

        _, secrets_only = run_json(["scan", str(root), "--only", "secrets"], capsys)
        assert {f["kind"] for f in secrets_only["findings"]} == {"secret"}

        _, two = run_json(["scan", str(root), "--only", "sast", "--only", "secrets"], capsys)
        assert {f["kind"] for f in two["findings"]} == {"sast", "secret"}

        _, sca_only = run_json(["scan", str(root), "--only", "sca"], capsys)
        assert sca_only["findings"] == []

    def test_exclude(self, write_tree: WriteTree) -> None:
        root = write_tree({"vendor/bad.py": "eval(x)\n", "ok.py": "y = 1\n"})
        assert main(["scan", str(root)]) == EXIT_FINDINGS
        assert main(["scan", str(root), "--exclude", "vendor"]) == EXIT_OK

    def test_exclude_adds_to_the_config_file_excludes(self, write_tree: WriteTree) -> None:
        root = write_tree(
            {
                ".dsscan.toml": 'exclude = ["one"]\n',
                "one/a.py": "eval(x)\n",
                "two/b.py": "eval(y)\n",
            }
        )
        assert main(["scan", str(root), "--exclude", "two"]) == EXIT_OK
        assert main(["scan", str(root)]) == EXIT_FINDINGS

    def test_custom_advisory_database(self, write_tree: WriteTree, tmp_path: Path) -> None:
        database = tmp_path / "custom.json"
        database.write_text(
            json.dumps(
                {
                    "schema_version": 1,
                    "advisories": [
                        {
                            "id": "TEST-0001",
                            "ecosystem": "PyPI",
                            "package": "demo-pkg",
                            "ranges": [{"fixed": "2.0"}],
                            "severity": "high",
                            "summary": "Test advisory.",
                        }
                    ],
                }
            ),
            encoding="utf-8",
        )
        root = write_tree({"requirements.txt": "demo-pkg==1.0\n"})
        assert main(["scan", str(root)]) == EXIT_OK
        assert main(["scan", str(root), "--advisories", str(database)]) == EXIT_FINDINGS

    def test_invalid_advisory_database_exits_two(
        self, write_tree: WriteTree, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        bad = tmp_path / "bad.json"
        bad.write_text("{nope", encoding="utf-8")
        code = main(["scan", str(write_tree(VULNERABLE)), "--advisories", str(bad)])
        assert code == EXIT_ERROR
        assert "advisory database" in capsys.readouterr().err


class TestConfigFile:
    def test_config_in_the_scanned_directory_is_used(self, write_tree: WriteTree) -> None:
        root = write_tree({**VULNERABLE, ".dsscan.toml": 'fail_on = "critical"\n'})
        assert main(["scan", str(root)]) == EXIT_OK

    def test_command_line_wins_over_the_config_file(self, write_tree: WriteTree) -> None:
        root = write_tree({**VULNERABLE, ".dsscan.toml": 'fail_on = "critical"\n'})
        assert main(["scan", str(root), "--fail-on", "high"]) == EXIT_FINDINGS

    def test_explicit_config_path(self, write_tree: WriteTree) -> None:
        root = write_tree({**VULNERABLE, "elsewhere/custom.toml": 'fail_on = "none"\n'})
        config_path = root / "elsewhere" / "custom.toml"
        assert main(["scan", str(root), "--config", str(config_path)]) == EXIT_OK

    def test_invalid_config_exits_two(
        self, write_tree: WriteTree, capsys: pytest.CaptureFixture[str]
    ) -> None:
        root = write_tree({**VULNERABLE, ".dsscan.toml": "fail_on = = broken"})
        assert main(["scan", str(root)]) == EXIT_ERROR
        assert "not valid TOML" in capsys.readouterr().err

    def test_missing_explicit_config_exits_two(self, write_tree: WriteTree, tmp_path: Path) -> None:
        root = write_tree(VULNERABLE)
        assert main(["scan", str(root), "--config", str(tmp_path / "absent.toml")]) == EXIT_ERROR


class TestRulesCommand:
    def test_lists_every_engine(self, capsys: pytest.CaptureFixture[str]) -> None:
        assert main(["rules"]) == EXIT_OK
        out = capsys.readouterr().out
        assert out.splitlines()[0].split() == ["RULE", "SEVERITY", "ENGINE", "TITLE"]
        for expected in ("SAST-001", "SECRET-AWS-ACCESS-KEY-ID", "CVE-2023-32681"):
            assert expected in out


class TestInvalidOptionValues:
    def test_blank_exclude_pattern_exits_two(
        self, write_tree: WriteTree, capsys: pytest.CaptureFixture[str]
    ) -> None:
        code = main(["scan", str(write_tree(VULNERABLE)), "--exclude", "   "])
        assert code == EXIT_ERROR
        assert "invalid command-line options" in capsys.readouterr().err



class TestBrokenPipe:
    """``dsscan ... | head`` must not print a traceback."""

    @staticmethod
    def _raise_broken_pipe(*_: object, **__: object) -> int:
        raise BrokenPipeError

    def test_rules_exits_quietly(
        self, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        monkeypatch.setattr("devsecops_scanner.cli._list_rules", self._raise_broken_pipe)
        assert main(["rules"]) == EXIT_OK
        assert capsys.readouterr().err == ""

    def test_scan_fails_closed_because_the_report_was_not_delivered(
        self,
        write_tree: WriteTree,
        monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        monkeypatch.setattr("devsecops_scanner.cli._scan", self._raise_broken_pipe)
        assert main(["scan", str(write_tree({"ok.py": "x = 1\n"}))]) == EXIT_ERROR
        assert capsys.readouterr().err == ""

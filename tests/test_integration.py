"""End-to-end tests: a realistic project scanned by the real engine, the CLI and itself."""

from __future__ import annotations

import json
import subprocess
import sys
import textwrap
from collections import defaultdict
from pathlib import Path

import pytest

from devsecops_scanner.bootstrap import build_engine
from devsecops_scanner.core.config import ScanConfig, load_config
from devsecops_scanner.core.models import FindingKind, ScanResult, Severity
from devsecops_scanner.reporting import JsonReporter, SarifReporter, TextReporter
from tests.conftest import WriteTree
from tests.helpers import HIGH_ENTROPY_VALUE, fake_aws_key_id, fake_github_token

REPO_ROOT = Path(__file__).resolve().parents[1]

LOCKFILE = json.dumps(
    {
        "lockfileVersion": 3,
        "packages": {
            "": {"name": "web"},
            "node_modules/lodash": {"version": "4.17.20"},
            "node_modules/left-pad": {"version": "1.3.0"},
        },
    },
    indent=2,
)


def project_files() -> dict[str, str]:
    source = textwrap.dedent(
        f"""\
        import hashlib
        import os
        import pickle
        import subprocess

        import requests
        import yaml

        AWS_KEY = "{fake_aws_key_id()}"


        def handler(user_input: str, blob: bytes) -> None:
            os.system("ping " + user_input)
            subprocess.run(user_input, shell=True)
            pickle.loads(blob)
            yaml.load(blob)
            hashlib.md5(blob)
            requests.get("https://example.org", verify=False)
            eval(user_input)  # dsscan: ignore[SAST-001]
        """
    )
    return {
        "app/main.py": source,
        "requirements.txt": "requests==2.25.1\nPyYAML==5.3.1\nflask>=2.0\n",
        "web/package-lock.json": LOCKFILE,
        ".env": f"API_KEY={HIGH_ENTROPY_VALUE}\n",
        # Everything below must be ignored by default:
        "node_modules/evil/index.py": "eval(x)\n",
        ".git/config": f'token = "{fake_github_token()}"\n',
    }


@pytest.fixture
def project(write_tree: WriteTree) -> Path:
    return write_tree(project_files())


def scan(root: Path) -> ScanResult:
    config = ScanConfig()
    return build_engine(config).scan(root, config)


def lines_by_rule(result: ScanResult) -> dict[str, list[int]]:
    grouped: dict[str, list[int]] = defaultdict(list)
    for finding in result.findings:
        grouped[finding.rule_id].append(finding.location.line)
    return {rule: sorted(lines) for rule, lines in grouped.items()}


class TestRealisticProject:
    def test_every_engine_contributes(self, project: Path) -> None:
        result = scan(project)
        assert {f.kind for f in result.findings} == set(FindingKind)

    def test_expected_findings_and_locations(self, project: Path) -> None:
        assert lines_by_rule(scan(project)) == {
            "SECRET-AWS-ACCESS-KEY-ID": [9],
            "SAST-002": [13, 14],
            "SAST-003": [15, 16],
            "SAST-004": [17],
            "SAST-005": [18],
            "CVE-2023-32681": [1],
            "CVE-2020-14343": [2],
            "CVE-2021-23337": [7],
            "SECRET-ENV-ASSIGNMENT": [1],
        }

    def test_inline_suppression_is_counted(self, project: Path) -> None:
        result = scan(project)
        assert result.suppressed == 1
        assert "SAST-001" not in lines_by_rule(result)

    def test_default_excluded_directories_are_ignored(self, project: Path) -> None:
        paths = {f.location.path for f in scan(project).findings}
        assert not any(p.startswith(("node_modules/", ".git/")) for p in paths)
        assert paths == {
            "app/main.py",
            "requirements.txt",
            "web/package-lock.json",
            ".env",
        }

    def test_unpinned_dependency_is_reported_as_a_coverage_warning(self, project: Path) -> None:
        result = scan(project)
        assert [(i.source, i.path) for i in result.issues] == [("sca", "requirements.txt")]
        assert result.has_errors is False

    def test_findings_are_ordered_by_severity(self, project: Path) -> None:
        ranks = [f.severity.rank for f in scan(project).findings]
        assert ranks == sorted(ranks, reverse=True)
        assert scan(project).findings[0].severity is Severity.CRITICAL

    def test_results_are_deterministic(self, project: Path) -> None:
        assert scan(project) == scan(project)
        assert JsonReporter().render(scan(project)) == JsonReporter().render(scan(project))

    def test_no_raw_secret_in_any_report(self, project: Path) -> None:
        result = scan(project)
        secrets = (fake_aws_key_id(), HIGH_ENTROPY_VALUE, fake_github_token())
        for reporter in (TextReporter(), JsonReporter(), SarifReporter()):
            rendered = reporter.render(result)
            for secret in secrets:
                assert secret not in rendered

    def test_sarif_for_the_project_is_well_formed(self, project: Path) -> None:
        log = json.loads(SarifReporter().render(scan(project)))
        run = log["runs"][0]
        rule_ids = {rule["id"] for rule in run["tool"]["driver"]["rules"]}
        assert {r["ruleId"] for r in run["results"]} == rule_ids
        assert all(r["partialFingerprints"]["dsscan/v1"] for r in run["results"])
        assert len({r["partialFingerprints"]["dsscan/v1"] for r in run["results"]}) == len(
            run["results"]
        )


class TestSubprocess:
    """Runs the installed entry point module exactly as a CI job would."""

    def _run(self, *args: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [sys.executable, "-m", "devsecops_scanner", *args],
            capture_output=True,
            text=True,
            timeout=120,
            check=False,
        )

    def test_exit_code_and_sarif_on_stdout(self, project: Path) -> None:
        completed = self._run("scan", str(project), "--format", "sarif")
        assert completed.returncode == 1, completed.stderr
        assert json.loads(completed.stdout)["version"] == "2.1.0"

    def test_clean_directory(self, write_tree: WriteTree) -> None:
        completed = self._run("scan", str(write_tree({"ok.py": "x = 1\n"})))
        assert completed.returncode == 0, completed.stderr
        assert "0 finding(s)" in completed.stdout

    def test_usage_error(self) -> None:
        completed = self._run("scan", "--fail-on", "nonsense")
        assert completed.returncode == 2
        assert "invalid choice" in completed.stderr


class TestDogfooding:
    """The scanner must pass its own checks, or it has no business gating other pipelines."""

    def test_package_source_is_clean(self) -> None:
        source = REPO_ROOT / "src"
        if not source.is_dir():
            pytest.skip("source tree not available (installed package)")
        result = scan(source)
        assert result.findings == ()
        assert result.issues == ()
        assert result.files_scanned > 20

    def test_whole_repository_passes_with_its_own_config(self) -> None:
        if not (REPO_ROOT / "pyproject.toml").is_file():
            pytest.skip("repository root not available (installed package)")
        config = load_config(None, root=REPO_ROOT)
        result = build_engine(config).scan(REPO_ROOT, config)
        assert result.findings == (), [f.fingerprint() for f in result.findings]
        assert result.has_errors is False

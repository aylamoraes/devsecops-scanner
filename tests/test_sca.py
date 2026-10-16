"""Unit and integration tests for the SCA checker."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from packaging.version import Version
from pydantic import ValidationError

from devsecops_scanner.core.errors import AdvisoryDataError, FileAnalysisError
from devsecops_scanner.core.models import Finding, FindingKind, IssueLevel, ScanIssue, Severity
from devsecops_scanner.sca import AdvisoryDatabase, ScaAnalyzer, load_advisories
from devsecops_scanner.sca.models import (
    Advisory,
    Ecosystem,
    VersionRange,
    normalize_name,
)
from devsecops_scanner.sca.parsers import PackageLockParser, RequirementsTxtParser
from tests.conftest import WriteTree
from tests.helpers import make_source


def analyzer() -> ScaAnalyzer:
    return ScaAnalyzer(AdvisoryDatabase(load_advisories()))


def findings_of(text: str, path: str) -> list[Finding]:
    return [i for i in analyzer().analyze(make_source(text, path)) if isinstance(i, Finding)]


def issues_of(text: str, path: str) -> list[ScanIssue]:
    return [i for i in analyzer().analyze(make_source(text, path)) if isinstance(i, ScanIssue)]


class TestVersionRange:
    @pytest.mark.parametrize(
        ("version", "expected"),
        [
            ("2.2.9", False),
            ("2.3.0", True),  # introduced is inclusive
            ("2.30.0", True),
            ("2.31.0", False),  # fixed is exclusive
            ("2.31.1", False),
        ],
    )
    def test_bounded_range(self, version: str, expected: bool) -> None:
        window = VersionRange(introduced="2.3.0", fixed="2.31.0")
        assert window.contains(Version(version)) is expected

    def test_open_start_means_since_the_first_release(self) -> None:
        assert VersionRange(fixed="1.0").contains(Version("0.0.1")) is True

    def test_open_end_means_no_fix_yet(self) -> None:
        assert VersionRange(introduced="2.0").contains(Version("99.0")) is True

    @pytest.mark.parametrize("value", ["not-a-version", "", "1.x"])
    def test_rejects_invalid_versions(self, value: str) -> None:
        with pytest.raises(ValidationError):
            VersionRange(introduced=value)

    def test_prerelease_is_before_the_release(self) -> None:
        # 2.0.0rc1 < 2.0.0, so it is NOT inside [2.0.0, 2.0.6).
        window = VersionRange(introduced="2.0.0", fixed="2.0.6")
        assert window.contains(Version("2.0.0rc1")) is False


class TestNormalizeName:
    @pytest.mark.parametrize(
        ("name", "expected"),
        [("PyYAML", "pyyaml"), ("Flask_SQLAlchemy", "flask-sqlalchemy"), ("a.b__c", "a-b-c")],
    )
    def test_pypi_follows_pep_503(self, name: str, expected: str) -> None:
        assert normalize_name(Ecosystem.PYPI, name) == expected

    def test_npm_is_lowercased_only(self) -> None:
        assert normalize_name(Ecosystem.NPM, "Lodash") == "lodash"
        assert normalize_name(Ecosystem.NPM, "@scope/Pkg_name") == "@scope/pkg_name"


class TestAdvisoryDatabase:
    def test_bundled_database_loads_and_is_consistent(self) -> None:
        advisories = load_advisories()
        assert {a.id for a in advisories} == {
            "CVE-2023-32681",
            "CVE-2020-14343",
            "CVE-2023-43804",
            "CVE-2021-23337",
        }
        for advisory in advisories:
            assert advisory.references
            assert advisory.cvss is not None

    def test_lookup_normalizes_names(self) -> None:
        database = AdvisoryDatabase(load_advisories())
        assert [a.id for a in database.lookup(Ecosystem.PYPI, "PYYAML")] == ["CVE-2020-14343"]
        assert database.lookup(Ecosystem.PYPI, "unknown-package") == ()

    def test_lookup_is_scoped_by_ecosystem(self) -> None:
        database = AdvisoryDatabase(load_advisories())
        assert database.lookup(Ecosystem.NPM, "requests") == ()
        assert len(database.lookup(Ecosystem.NPM, "lodash")) == 1

    def test_len(self) -> None:
        assert len(AdvisoryDatabase(load_advisories())) == 4

    def test_matching_range_picks_the_right_interval(self) -> None:
        urllib3 = next(a for a in load_advisories() if a.package == "urllib3")
        assert urllib3.matching_range(Version("1.26.16")) == VersionRange(fixed="1.26.17")
        expected = VersionRange(introduced="2.0.0", fixed="2.0.6")
        assert urllib3.matching_range(Version("2.0.5")) == expected
        assert urllib3.matching_range(Version("1.26.17")) is None
        assert urllib3.matching_range(Version("2.0.6")) is None


class TestLoadAdvisories:
    def _write(self, tmp_path: Path, payload: object) -> Path:
        path = tmp_path / "db.json"
        path.write_text(json.dumps(payload), encoding="utf-8")
        return path

    @staticmethod
    def _advisory(advisory_id: str = "TEST-1") -> dict[str, object]:
        return {
            "id": advisory_id,
            "ecosystem": "PyPI",
            "package": "demo",
            "ranges": [{"introduced": "1.0", "fixed": "1.5"}],
            "severity": "high",
            "summary": "A test advisory.",
        }

    def test_loads_a_custom_database(self, tmp_path: Path) -> None:
        path = self._write(tmp_path, {"schema_version": 1, "advisories": [self._advisory()]})
        (advisory,) = load_advisories(path)
        assert isinstance(advisory, Advisory)
        assert advisory.severity is Severity.HIGH

    def test_missing_file(self, tmp_path: Path) -> None:
        with pytest.raises(AdvisoryDataError, match="could not be read"):
            load_advisories(tmp_path / "absent.json")

    def test_invalid_json(self, tmp_path: Path) -> None:
        path = tmp_path / "db.json"
        path.write_text("{not json", encoding="utf-8")
        with pytest.raises(AdvisoryDataError, match="failed validation"):
            load_advisories(path)

    def test_unknown_schema_version(self, tmp_path: Path) -> None:
        path = self._write(tmp_path, {"schema_version": 2, "advisories": []})
        with pytest.raises(AdvisoryDataError, match="schema_version"):
            load_advisories(path)

    def test_duplicate_ids_are_rejected(self, tmp_path: Path) -> None:
        payload = {"schema_version": 1, "advisories": [self._advisory(), self._advisory()]}
        with pytest.raises(AdvisoryDataError, match="duplicate"):
            load_advisories(self._write(tmp_path, payload))

    def test_unknown_fields_are_rejected(self, tmp_path: Path) -> None:
        bad = {**self._advisory(), "surprise": 1}
        with pytest.raises(AdvisoryDataError, match="failed validation"):
            load_advisories(self._write(tmp_path, {"schema_version": 1, "advisories": [bad]}))

    def test_validation_error_does_not_echo_values(self, tmp_path: Path) -> None:
        marker = "LEAK-MARKER-42"
        bad = {**self._advisory(), "severity": marker}
        with pytest.raises(AdvisoryDataError) as info:
            load_advisories(self._write(tmp_path, {"schema_version": 1, "advisories": [bad]}))
        assert "severity" in str(info.value)
        assert marker not in str(info.value)

    def test_advisory_without_ranges_is_rejected(self, tmp_path: Path) -> None:
        bad = {**self._advisory(), "ranges": []}
        with pytest.raises(AdvisoryDataError):
            load_advisories(self._write(tmp_path, {"schema_version": 1, "advisories": [bad]}))


class TestRequirementsParser:
    parser = RequirementsTxtParser()

    @pytest.mark.parametrize(
        ("path", "expected"),
        [
            ("requirements.txt", True),
            ("requirements-dev.txt", True),
            ("requirements_test.txt", True),
            ("deploy/Requirements.TXT", True),
            ("dev-requirements.txt", True),
            ("readme.txt", False),
            ("requirements.md", False),
            ("package-lock.json", False),
        ],
    )
    def test_matches(self, path: str, expected: bool) -> None:
        assert self.parser.matches(path) is expected

    def test_parses_exact_pins(self) -> None:
        text = (
            "requests==2.25.1\n"
            "PyYAML == 5.3.1  # inline comment\n"
            "numpy===1.26.0\n"
            "django[argon2]==3.2\n"
        )
        result = self.parser.parse(make_source(text, "requirements.txt"))
        assert [(d.name, d.version, d.location.line) for d in result.dependencies] == [
            ("requests", "2.25.1", 1),
            ("PyYAML", "5.3.1", 2),
            ("numpy", "1.26.0", 3),
            ("django", "3.2", 4),
        ]
        assert result.unchecked == 0
        assert all(d.ecosystem is Ecosystem.PYPI for d in result.dependencies)

    def test_ignores_comments_blank_lines_and_options(self) -> None:
        text = "# header\n\n-r base.txt\n--index-url https://example.org/simple\n-e .\n"
        result = self.parser.parse(make_source(text, "requirements.txt"))
        assert result.dependencies == ()
        assert result.unchecked == 0

    def test_counts_unpinned_entries_as_unchecked(self) -> None:
        text = "flask>=2.0\nrequests~=2.0\nfoo==1.*\ngit+https://example.org/x.git\nok==1.0\n"
        result = self.parser.parse(make_source(text, "requirements.txt"))
        assert [d.name for d in result.dependencies] == ["ok"]
        assert result.unchecked == 4

    def test_handles_markers_hashes_and_continuations(self) -> None:
        text = (
            'numpy==1.26.0 ; python_version >= "3.9"\n'
            "pkg==1.0 \\\n"
            "    --hash=sha256:abc123 \\\n"
            "    --hash=sha256:def456\n"
            "after==2.0\n"
        )
        result = self.parser.parse(make_source(text, "requirements.txt"))
        assert [(d.name, d.version, d.location.line) for d in result.dependencies] == [
            ("numpy", "1.26.0", 1),
            ("pkg", "1.0", 2),
            ("after", "2.0", 5),
        ]

    def test_empty_file(self) -> None:
        result = self.parser.parse(make_source("", "requirements.txt"))
        assert result.dependencies == ()
        assert result.unchecked == 0


LOCK_V3 = """{
  "name": "demo",
  "lockfileVersion": 3,
  "packages": {
    "": { "name": "demo", "version": "1.0.0" },
    "node_modules/lodash": { "version": "4.17.20" },
    "node_modules/a/node_modules/lodash": { "version": "3.0.0" },
    "node_modules/alias": { "name": "real-name", "version": "1.2.3" },
    "node_modules/linked": { "link": true, "resolved": "../linked" },
    "packages/workspace": { "version": "0.0.1" }
  }
}
"""

LOCK_V1 = """{
  "lockfileVersion": 1,
  "dependencies": {
    "lodash": {
      "version": "4.17.20",
      "dependencies": {
        "minimist": { "version": "1.2.0" }
      }
    }
  }
}
"""


class TestPackageLockParser:
    parser = PackageLockParser()

    def test_matches_only_package_lock(self) -> None:
        assert self.parser.matches("package-lock.json") is True
        assert self.parser.matches("web/package-lock.json") is True
        assert self.parser.matches("package.json") is False
        assert self.parser.matches("yarn.lock") is False

    def test_parses_lockfile_v3(self) -> None:
        result = self.parser.parse(make_source(LOCK_V3, "package-lock.json"))
        pairs = sorted((d.name, d.version) for d in result.dependencies)
        assert pairs == [("lodash", "3.0.0"), ("lodash", "4.17.20"), ("real-name", "1.2.3")]
        assert all(d.ecosystem is Ecosystem.NPM for d in result.dependencies)

    def test_reports_the_line_of_the_entry(self) -> None:
        result = self.parser.parse(make_source(LOCK_V3, "package-lock.json"))
        lodash = next(d for d in result.dependencies if d.version == "4.17.20")
        assert lodash.location.line == 6

    def test_parses_legacy_nested_dependencies(self) -> None:
        result = self.parser.parse(make_source(LOCK_V1, "package-lock.json"))
        assert sorted((d.name, d.version) for d in result.dependencies) == [
            ("lodash", "4.17.20"),
            ("minimist", "1.2.0"),
        ]

    def test_invalid_json_is_a_file_error(self) -> None:
        with pytest.raises(FileAnalysisError, match="not valid JSON"):
            self.parser.parse(make_source("{broken", "package-lock.json"))

    def test_non_object_json_is_a_file_error(self) -> None:
        with pytest.raises(FileAnalysisError, match="unexpected structure"):
            self.parser.parse(make_source("[1, 2]", "package-lock.json"))

    def test_malformed_entries_are_skipped(self) -> None:
        text = '{"packages": {"node_modules/a": 5, "node_modules/b": {"version": 7}, "x": null}}'
        result = self.parser.parse(make_source(text, "package-lock.json"))
        assert result.dependencies == ()

    def test_minified_json_still_parses(self) -> None:
        minified = json.dumps(json.loads(LOCK_V3))
        result = self.parser.parse(make_source(minified, "package-lock.json"))
        assert len(result.dependencies) == 3


class TestScaAnalyzer:
    def test_accepts_manifests_only(self) -> None:
        sca = analyzer()
        assert sca.accepts("requirements.txt") is True
        assert sca.accepts("web/package-lock.json") is True
        assert sca.accepts("main.py") is False
        assert sca.name == "sca"

    def test_reports_vulnerable_python_pins(self) -> None:
        text = "requests==2.25.1\nPyYAML==5.3.1\nurllib3==1.26.5\nflask==3.0.0\n"
        found = findings_of(text, "requirements.txt")
        assert [(f.rule_id, f.severity, f.location.line) for f in found] == [
            ("CVE-2023-32681", Severity.MEDIUM, 1),
            ("CVE-2020-14343", Severity.CRITICAL, 2),
            ("CVE-2023-43804", Severity.MEDIUM, 3),
        ]
        assert all(f.kind is FindingKind.SCA for f in found)

    def test_fixed_versions_are_clean(self) -> None:
        text = "requests==2.31.0\nPyYAML==5.4\nurllib3==1.26.17\nurllib3==2.0.6\n"
        assert findings_of(text, "requirements.txt") == []

    def test_remediation_names_the_fixed_version(self) -> None:
        (finding,) = findings_of("requests==2.25.1\n", "requirements.txt")
        assert finding.remediation == "Upgrade requests to 2.31.0 or later."
        assert "CVE-2023-32681" in finding.message
        assert finding.snippet == "requests 2.25.1"

    def test_package_name_matching_is_normalized(self) -> None:
        found = findings_of("pyyaml==5.3.1\nPYYAML==5.3.1\n", "requirements.txt")
        assert len(found) == 2

    def test_reports_vulnerable_npm_packages(self) -> None:
        found = findings_of(LOCK_V3, "package-lock.json")
        assert {(f.rule_id, f.severity) for f in found} == {("CVE-2021-23337", Severity.HIGH)}
        assert sorted(f.snippet or "" for f in found) == ["lodash 3.0.0", "lodash 4.17.20"]

    def test_patched_npm_package_is_clean(self) -> None:
        patched = LOCK_V3.replace("4.17.20", "4.17.21").replace('"3.0.0"', '"4.17.21"')
        assert findings_of(patched, "package-lock.json") == []

    def test_unpinned_entries_produce_a_coverage_warning(self) -> None:
        (issue,) = issues_of("flask>=2.0\nrequests==2.31.0\n", "requirements.txt")
        assert issue.level is IssueLevel.WARNING
        assert issue.path == "requirements.txt"
        assert "1 dependency entries were not checked" in issue.message

    def test_non_standard_version_counts_as_unchecked(self) -> None:
        (issue,) = issues_of("foo==not.a.version!\n", "requirements.txt")
        assert "1 dependency entries were not checked" in issue.message

    def test_no_warning_when_everything_was_checked(self) -> None:
        assert issues_of("requests==2.31.0\n", "requirements.txt") == []

    def test_rules_listing_covers_every_advisory(self) -> None:
        rules = analyzer().rules()
        assert len(rules) == 4
        assert all(r.kind is FindingKind.SCA for r in rules)
        assert {r.rule_id for r in rules} == {a.id for a in load_advisories()}

    def test_end_to_end_with_files(self, write_tree: WriteTree) -> None:
        from devsecops_scanner.core.config import ScanConfig
        from devsecops_scanner.core.engine import ScanEngine

        root = write_tree({"requirements.txt": "requests==2.25.1\n", "src/main.py": "x = 1\n"})
        result = ScanEngine([analyzer()]).scan(root, ScanConfig())
        assert [f.rule_id for f in result.findings] == ["CVE-2023-32681"]


class TestParserEdgeCases:
    def test_trailing_continuation_at_end_of_file(self) -> None:
        result = RequirementsTxtParser().parse(make_source("pkg==1.0 \\", "requirements.txt"))
        assert [(d.name, d.version) for d in result.dependencies] == [("pkg", "1.0")]

    def test_legacy_lockfile_skips_non_object_entries(self) -> None:
        text = json.dumps({"dependencies": {"a": 5, "b": {"version": "1.0.0"}}})
        result = PackageLockParser().parse(make_source(text, "package-lock.json"))
        assert [d.name for d in result.dependencies] == ["b"]

    def test_legacy_lockfile_nesting_is_bounded(self) -> None:
        node: dict[str, object] = {"version": "1.0.0"}
        for index in range(100):
            node = {"version": f"1.0.{index}", "dependencies": {f"pkg{index}": node}}
        text = json.dumps({"dependencies": {"root": node}})
        result = PackageLockParser().parse(make_source(text, "package-lock.json"))
        assert 0 < len(result.dependencies) < 100

    def test_absurdly_long_names_and_versions_are_ignored(self) -> None:
        text = json.dumps(
            {
                "packages": {
                    "node_modules/" + "a" * 300: {"version": "1.0.0"},
                    "node_modules/ok": {"version": "1" * 200},
                    "node_modules/fine": {"version": "2.0.0"},
                }
            }
        )
        result = PackageLockParser().parse(make_source(text, "package-lock.json"))
        assert [d.name for d in result.dependencies] == ["fine"]


class TestAdvisoryLimits:
    def test_oversized_database_is_rejected(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        path = tmp_path / "db.json"
        path.write_text(json.dumps({"schema_version": 1, "advisories": []}), encoding="utf-8")
        monkeypatch.setattr("devsecops_scanner.sca.advisories._MAX_DATABASE_BYTES", 5)
        with pytest.raises(AdvisoryDataError, match="too large"):
            load_advisories(path)


class TestRemediation:
    def test_advisory_without_a_fix_says_so(self) -> None:
        advisory = Advisory(
            id="TEST-NOFIX",
            ecosystem=Ecosystem.PYPI,
            package="demo",
            ranges=(VersionRange(introduced="1.0"),),
            severity=Severity.HIGH,
            summary="No fix is available.",
        )
        sca = ScaAnalyzer(AdvisoryDatabase([advisory]))
        items = sca.analyze(make_source("demo==1.5\n", "requirements.txt"))
        (finding,) = [item for item in items if isinstance(item, Finding)]
        assert finding.remediation is not None
        assert "No fixed version" in finding.remediation

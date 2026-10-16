"""Unit tests for configuration validation and loading."""

from __future__ import annotations

from pathlib import Path

import pytest
from pydantic import ValidationError

from devsecops_scanner.core.config import (
    CONFIG_FILENAME,
    AnalyzerName,
    ScanConfig,
    load_config,
)
from devsecops_scanner.core.errors import ConfigError
from devsecops_scanner.core.models import Severity
from tests.conftest import WriteTree


class TestScanConfig:
    def test_defaults_are_safe(self) -> None:
        config = ScanConfig()
        assert config.fail_on is Severity.HIGH
        assert config.analyzers == frozenset(AnalyzerName)
        assert config.exclude == ()
        assert config.advisories_path is None

    def test_none_string_disables_failing(self) -> None:
        assert ScanConfig.model_validate({"fail_on": "none"}).fail_on is None
        assert ScanConfig.model_validate({"fail_on": " NONE "}).fail_on is None

    def test_severity_names_are_parsed(self) -> None:
        assert ScanConfig.model_validate({"fail_on": "critical"}).fail_on is Severity.CRITICAL

    @pytest.mark.parametrize(
        "data",
        [
            {"fail_on": "urgent"},
            {"max_file_size_bytes": 10},
            {"max_file_size_bytes": 10**9},
            {"exclude": ["ok", "   "]},
            {"analyzers": []},
            {"analyzers": ["sast", "nonsense"]},
            {"unknown_key": 1},
        ],
    )
    def test_rejects_invalid_values(self, data: dict[str, object]) -> None:
        with pytest.raises(ValidationError):
            ScanConfig.model_validate(data)

    def test_is_immutable(self) -> None:
        with pytest.raises(ValidationError):
            ScanConfig().fail_on = Severity.LOW  # type: ignore[misc]


class TestLoadConfig:
    def test_defaults_without_file(self, write_tree: WriteTree) -> None:
        root = write_tree({"app.py": "x = 1\n"})
        assert load_config(None, root=root) == ScanConfig()

    def test_picks_up_file_in_root(self, write_tree: WriteTree) -> None:
        root = write_tree({CONFIG_FILENAME: 'fail_on = "critical"\nexclude = ["docs"]\n'})
        config = load_config(None, root=root)
        assert config.fail_on is Severity.CRITICAL
        assert config.exclude == ("docs",)

    def test_single_file_root_uses_its_directory(self, write_tree: WriteTree) -> None:
        root = write_tree({CONFIG_FILENAME: 'fail_on = "low"\n', "one.py": "x = 1\n"})
        assert load_config(None, root=root / "one.py").fail_on is Severity.LOW

    def test_explicit_path_wins_over_root_file(self, write_tree: WriteTree) -> None:
        root = write_tree(
            {CONFIG_FILENAME: 'fail_on = "low"\n', "custom.toml": 'fail_on = "medium"\n'}
        )
        assert load_config(root / "custom.toml", root=root).fail_on is Severity.MEDIUM

    def test_missing_explicit_file_is_an_error(self, tmp_path: Path) -> None:
        with pytest.raises(ConfigError, match="not found"):
            load_config(tmp_path / "nope.toml", root=tmp_path)

    def test_invalid_toml_is_an_error(self, write_tree: WriteTree) -> None:
        root = write_tree({CONFIG_FILENAME: "fail_on = = broken"})
        with pytest.raises(ConfigError, match="not valid TOML"):
            load_config(None, root=root)

    def test_invalid_value_error_does_not_echo_the_value(self, write_tree: WriteTree) -> None:
        marker = "TOP-SECRET-MARKER"
        root = write_tree({CONFIG_FILENAME: f'fail_on = "{marker}"\n'})
        with pytest.raises(ConfigError) as info:
            load_config(None, root=root)
        assert "fail_on" in str(info.value)
        assert marker not in str(info.value)

    def test_unknown_key_is_reported(self, write_tree: WriteTree) -> None:
        root = write_tree({CONFIG_FILENAME: "bogus = 1\n"})
        with pytest.raises(ConfigError, match="bogus"):
            load_config(None, root=root)

    def test_relative_advisories_path_is_relative_to_the_config_file(
        self, write_tree: WriteTree
    ) -> None:
        root = write_tree({"conf/.dsscan.toml": 'advisories_path = "db.json"\n'})
        config = load_config(root / "conf" / ".dsscan.toml", root=root)
        assert config.advisories_path == root / "conf" / "db.json"

    def test_oversized_config_is_rejected(self, write_tree: WriteTree) -> None:
        root = write_tree({CONFIG_FILENAME: "# " + "x" * 70_000 + "\n"})
        with pytest.raises(ConfigError, match="too large"):
            load_config(None, root=root)


class TestUndecodableConfig:
    def test_non_utf8_config_is_an_error(self, tmp_path: Path) -> None:
        (tmp_path / CONFIG_FILENAME).write_bytes(b"\xff\xfe\x00bad")
        with pytest.raises(ConfigError, match="could not be read"):
            load_config(None, root=tmp_path)

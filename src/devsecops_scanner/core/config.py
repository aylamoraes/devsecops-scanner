"""Scan configuration: validated model plus a TOML loader.

Precedence (lowest to highest): built-in defaults, ``.dsscan.toml``, command-line flags.
"""

from __future__ import annotations

import tomllib
from enum import StrEnum
from pathlib import Path
from typing import Any, Final

from pydantic import Field, ValidationError, field_validator

from devsecops_scanner.core.errors import ConfigError
from devsecops_scanner.core.models import FrozenModel, Severity

CONFIG_FILENAME: Final = ".dsscan.toml"
MAX_CONFIG_BYTES: Final = 64 * 1024

# Directories that are never scanned: VCS metadata, virtual environments, caches and
# build output. Dependencies are the SCA engine's job, not the SAST engine's.
DEFAULT_EXCLUDED_DIRS: Final[tuple[str, ...]] = (
    ".git",
    ".hg",
    ".svn",
    ".venv",
    "venv",
    "node_modules",
    "__pycache__",
    ".mypy_cache",
    ".pytest_cache",
    ".ruff_cache",
    ".tox",
    ".idea",
    ".vscode",
    "dist",
    "build",
    "*.egg-info",
)


class AnalyzerName(StrEnum):
    """Names accepted by ``--only`` and by the ``analyzers`` config key."""

    SAST = "sast"
    SCA = "sca"
    SECRETS = "secrets"


class ScanConfig(FrozenModel):
    """Validated scan settings."""

    exclude: tuple[str, ...] = ()
    fail_on: Severity | None = Severity.HIGH
    max_file_size_bytes: int = Field(default=1_000_000, ge=1_024, le=50_000_000)
    analyzers: frozenset[AnalyzerName] = frozenset(AnalyzerName)
    advisories_path: Path | None = None

    @field_validator("fail_on", mode="before")
    @classmethod
    def _none_means_never_fail(cls, value: object) -> object:
        # TOML has no null, so the string "none" is the way to say "never fail".
        if isinstance(value, str) and value.strip().lower() == "none":
            return None
        return value

    @field_validator("exclude")
    @classmethod
    def _no_blank_patterns(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if any(not pattern.strip() for pattern in value):
            raise ValueError("exclude patterns must not be blank")
        return value

    @field_validator("analyzers")
    @classmethod
    def _at_least_one_analyzer(cls, value: frozenset[AnalyzerName]) -> frozenset[AnalyzerName]:
        if not value:
            raise ValueError("at least one analyzer must be enabled")
        return value


def load_config(explicit_path: Path | None, *, root: Path) -> ScanConfig:
    """Load the configuration.

    ``explicit_path`` (from ``--config``) must exist. Without it, ``<root>/.dsscan.toml``
    is used when present; otherwise the defaults apply.
    """
    if explicit_path is not None:
        if not explicit_path.is_file():
            raise ConfigError("configuration file not found")
        return _parse(explicit_path)

    base = root if root.is_dir() else root.parent
    candidate = base / CONFIG_FILENAME
    if candidate.is_file():
        return _parse(candidate)
    return ScanConfig()


def _parse(path: Path) -> ScanConfig:
    try:
        if path.stat().st_size > MAX_CONFIG_BYTES:
            raise ConfigError("configuration file is too large")
        data: dict[str, Any] = tomllib.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError) as exc:
        raise ConfigError("configuration file could not be read") from exc
    except tomllib.TOMLDecodeError as exc:
        raise ConfigError("configuration file is not valid TOML") from exc

    advisories = data.get("advisories_path")
    if isinstance(advisories, str) and not Path(advisories).is_absolute():
        # Relative paths are relative to the config file, not to the working directory.
        data["advisories_path"] = str(path.parent / advisories)

    try:
        return ScanConfig.model_validate(data)
    except ValidationError as exc:
        # Report field names and reasons only; never echo the offending values.
        details = "; ".join(
            f"{'.'.join(str(part) for part in err['loc']) or '<root>'}: {err['msg']}"
            for err in exc.errors(include_input=False)
        )
        raise ConfigError(f"invalid configuration: {details}") from exc

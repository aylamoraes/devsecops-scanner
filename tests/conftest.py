"""Shared fixtures."""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path

import pytest

from devsecops_scanner.core.config import ScanConfig

WriteTree = Callable[[dict[str, str]], Path]


@pytest.fixture
def config() -> ScanConfig:
    """Default scan configuration."""
    return ScanConfig()


@pytest.fixture
def write_tree(tmp_path: Path) -> WriteTree:
    """Create files under ``tmp_path`` from a ``{relative_path: content}`` mapping."""

    def _write(files: dict[str, str]) -> Path:
        for relative, content in files.items():
            target = tmp_path / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(content, encoding="utf-8")
        return tmp_path

    return _write

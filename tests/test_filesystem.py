"""Unit tests for safe file discovery."""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from devsecops_scanner.core.config import ScanConfig
from devsecops_scanner.core.filesystem import SourceFile, is_excluded, iter_sources
from devsecops_scanner.core.models import IssueLevel, ScanIssue
from tests.conftest import WriteTree


def collect(
    root: Path, config: ScanConfig | None = None
) -> tuple[list[SourceFile], list[ScanIssue]]:
    sources: list[SourceFile] = []
    issues: list[ScanIssue] = []
    for item in iter_sources(root, config or ScanConfig()):
        if isinstance(item, SourceFile):
            sources.append(item)
        else:
            issues.append(item)
    return sources, issues


class TestSourceFile:
    def test_splits_on_the_same_line_breaks_as_python(self) -> None:
        # Form feed and U+2028 must NOT start a new line: ``ast`` does not count them.
        source = SourceFile.from_text("a.py", "one\x0ctwo\u2028three\r\nfour\rfive\nsix")
        assert source.lines == ("one\x0ctwo\u2028three", "four", "five", "six")

    def test_line_text_is_one_based_and_bounded(self) -> None:
        source = SourceFile.from_text("a.py", "first\nsecond")
        assert source.line_text(1) == "first"
        assert source.line_text(2) == "second"
        assert source.line_text(0) == ""
        assert source.line_text(3) == ""


class TestIsExcluded:
    @pytest.mark.parametrize(
        ("path", "patterns", "expected"),
        [
            ("tests/test_a.py", ["tests"], True),
            ("src/tests/test_a.py", ["tests"], True),
            ("src/app.py", ["tests"], False),
            ("docs/readme.md", ["*.md"], True),
            ("docs/readme.txt", ["*.md"], False),
            ("docs/examples/a.py", ["docs/examples"], True),
            ("docs/examples", ["docs/examples"], True),
            ("src/docs/examples/a.py", ["docs/examples"], False),
            ("docs/other/a.py", ["docs/examples"], False),
            ("a.py", ["", "   "], False),
            ("a.py", [], False),
            ("tests/a.py", ["tests/"], True),
        ],
    )
    def test_matching(self, path: str, patterns: list[str], expected: bool) -> None:
        assert is_excluded(path, patterns) is expected


class TestIterSources:
    def test_reads_text_files_with_relative_posix_paths(self, write_tree: WriteTree) -> None:
        root = write_tree({"a.py": "x = 1\n", "pkg/b.py": "y = 2\n"})
        sources, issues = collect(root)
        assert [s.path for s in sources] == ["a.py", "pkg/b.py"]
        assert issues == []

    def test_scans_a_single_file(self, write_tree: WriteTree) -> None:
        root = write_tree({"only.py": "x = 1\n", "other.py": "y = 2\n"})
        sources, _ = collect(root / "only.py")
        assert [s.path for s in sources] == ["only.py"]

    @pytest.mark.parametrize(
        "directory",
        [".git", "node_modules", ".venv", "__pycache__", "dist", "build", "foo.egg-info"],
    )
    def test_skips_default_excluded_directories(
        self, write_tree: WriteTree, directory: str
    ) -> None:
        root = write_tree({f"{directory}/x.py": "x = 1\n", "keep.py": "y = 2\n"})
        sources, _ = collect(root)
        assert [s.path for s in sources] == ["keep.py"]

    def test_honours_user_excludes(self, write_tree: WriteTree) -> None:
        root = write_tree({"tests/t.py": "x\n", "src/s.py": "y\n", "notes.md": "z\n"})
        config = ScanConfig(exclude=("tests", "*.md"))
        sources, _ = collect(root, config)
        assert [s.path for s in sources] == ["src/s.py"]

    def test_skips_binary_files_silently(self, write_tree: WriteTree, tmp_path: Path) -> None:
        root = write_tree({"text.txt": "hello\n"})
        (tmp_path / "blob.bin").write_bytes(b"\x89PNG\x00\x00binary")
        sources, issues = collect(root)
        assert [s.path for s in sources] == ["text.txt"]
        assert issues == []

    def test_oversized_file_is_skipped_with_a_warning(self, write_tree: WriteTree) -> None:
        root = write_tree({"big.txt": "a" * 5000, "small.txt": "b\n"})
        config = ScanConfig(max_file_size_bytes=1024)
        sources, issues = collect(root, config)
        assert [s.path for s in sources] == ["small.txt"]
        assert len(issues) == 1
        assert issues[0].level is IssueLevel.WARNING
        assert issues[0].path == "big.txt"
        assert "larger than" in issues[0].message

    def test_invalid_utf8_is_replaced_not_fatal(self, tmp_path: Path) -> None:
        (tmp_path / "latin.txt").write_bytes(b"caf\xe9 = 1\n")
        sources, issues = collect(tmp_path)
        assert len(sources) == 1
        assert "caf" in sources[0].text
        assert issues == []

    def test_strips_utf8_bom(self, tmp_path: Path) -> None:
        (tmp_path / "bom.py").write_bytes(b"\xef\xbb\xbfx = 1\n")
        sources, _ = collect(tmp_path)
        assert sources[0].text.startswith("x = 1")

    def test_order_is_deterministic(self, write_tree: WriteTree) -> None:
        root = write_tree({"b.py": "1\n", "a.py": "2\n", "c/z.py": "3\n", "c/y.py": "4\n"})
        expected = ["a.py", "b.py", "c/y.py", "c/z.py"]
        assert [s.path for s in collect(root)[0]] == expected
        assert [s.path for s in collect(root)[0]] == expected


@pytest.mark.skipif(not hasattr(os, "symlink"), reason="symlinks not supported")
class TestSymlinks:
    def _symlink(self, link: Path, target: Path) -> None:
        try:
            link.symlink_to(target)
        except (OSError, NotImplementedError):
            pytest.skip("cannot create symlinks on this system")

    def test_symlinked_file_is_not_followed(self, tmp_path: Path) -> None:
        outside = tmp_path / "outside"
        outside.mkdir()
        (outside / "secret.txt").write_text("do not read\n", encoding="utf-8")
        root = tmp_path / "root"
        root.mkdir()
        (root / "real.txt").write_text("ok\n", encoding="utf-8")
        self._symlink(root / "link.txt", outside / "secret.txt")

        sources, issues = collect(root)
        assert [s.path for s in sources] == ["real.txt"]
        assert [i.message for i in issues] == ["symbolic link not followed"]

    def test_symlinked_directory_is_not_followed(self, tmp_path: Path) -> None:
        outside = tmp_path / "outside"
        outside.mkdir()
        (outside / "secret.py").write_text("x = 1\n", encoding="utf-8")
        root = tmp_path / "root"
        root.mkdir()
        (root / "real.py").write_text("y = 2\n", encoding="utf-8")
        self._symlink(root / "linked_dir", outside)

        sources, _ = collect(root)
        assert [s.path for s in sources] == ["real.py"]


class TestUnreadableFiles:
    def test_read_errors_become_a_warning_not_a_crash(
        self, write_tree: WriteTree, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        root = write_tree({"a.txt": "x\n"})

        def deny(self: Path) -> bytes:
            raise PermissionError("denied")

        monkeypatch.setattr(Path, "read_bytes", deny)
        sources, issues = collect(root)
        assert sources == []
        assert [i.message for i in issues] == ["skipped: file could not be read"]
        assert issues[0].path == "a.txt"

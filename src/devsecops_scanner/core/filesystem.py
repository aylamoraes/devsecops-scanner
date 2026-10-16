"""Safe file discovery.

Security properties:

* Symbolic links are never followed, so a hostile repository cannot make the scanner
  read files outside the scan root.
* Files above ``max_file_size_bytes`` are skipped (with a warning), which bounds memory.
* Binary files are skipped silently.
* Paths handed to analyzers are relative and POSIX-style.
"""

from __future__ import annotations

import os
import re
from collections.abc import Iterable, Iterator
from dataclasses import dataclass
from fnmatch import fnmatchcase
from pathlib import Path, PurePosixPath
from typing import Final

from devsecops_scanner.core.config import DEFAULT_EXCLUDED_DIRS, ScanConfig
from devsecops_scanner.core.models import IssueLevel, ScanIssue

_BINARY_SNIFF_BYTES: Final = 8192
# Only \n, \r\n and \r end a line. str.splitlines() also splits on form feed, \x1c-\x1e,
# \x85 and U+2028/9, which would make our line numbers disagree with Python's ``ast``.
_LINE_BREAK: Final = re.compile(r"\r\n|\r|\n")
_SOURCE: Final = "filesystem"


@dataclass(frozen=True, slots=True)
class SourceFile:
    """A text file loaded in memory."""

    path: str  # relative to the scan root, forward slashes
    text: str
    lines: tuple[str, ...]

    @classmethod
    def from_text(cls, path: str, text: str) -> SourceFile:
        """Build a :class:`SourceFile`, splitting lines the same way ``ast`` counts them."""
        return cls(path=path, text=text, lines=tuple(_LINE_BREAK.split(text)))

    def line_text(self, line_number: int) -> str:
        """Return the 1-based line, or an empty string when out of range."""
        if 1 <= line_number <= len(self.lines):
            return self.lines[line_number - 1]
        return ""


def is_excluded(relative_posix: str, patterns: Iterable[str]) -> bool:
    """Decide whether a relative POSIX path matches any exclude pattern.

    * A pattern without ``/`` matches any single path component (``tests`` excludes
      ``tests/`` wherever it appears; ``*.md`` excludes every Markdown file).
    * A pattern with ``/`` matches the path from the root (``docs/examples`` excludes
      that directory and everything under it).
    """
    parts = PurePosixPath(relative_posix).parts
    for raw in patterns:
        pattern = raw.strip().rstrip("/")
        if not pattern:
            continue
        if "/" not in pattern:
            if any(fnmatchcase(part, pattern) for part in parts):
                return True
        elif fnmatchcase(relative_posix, pattern) or fnmatchcase(relative_posix, f"{pattern}/*"):
            return True
    return False


def iter_sources(root: Path, config: ScanConfig) -> Iterator[SourceFile | ScanIssue]:
    """Yield every scannable text file under ``root`` (or ``root`` itself if it is a file).

    Problems (unreadable or oversized files, symlinks) are yielded as :class:`ScanIssue`
    so the caller can report them instead of failing.
    """
    root = root.resolve()
    if root.is_file():
        yield from _read(root, root.name, config)
        return

    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        current = Path(dirpath)
        relative_dir = current.relative_to(root)

        dirnames[:] = sorted(
            name
            for name in dirnames
            if not _skip_directory(current / name, (relative_dir / name).as_posix(), config)
        )

        for name in sorted(filenames):
            relative = (relative_dir / name).as_posix()
            if is_excluded(relative, config.exclude):
                continue
            file_path = current / name
            if file_path.is_symlink():
                yield ScanIssue(
                    level=IssueLevel.WARNING,
                    source=_SOURCE,
                    path=relative,
                    message="symbolic link not followed",
                )
                continue
            yield from _read(file_path, relative, config)


def _skip_directory(path: Path, relative: str, config: ScanConfig) -> bool:
    if path.is_symlink():
        return True
    if any(fnmatchcase(path.name, pattern) for pattern in DEFAULT_EXCLUDED_DIRS):
        return True
    return is_excluded(relative, config.exclude)


def _read(path: Path, relative: str, config: ScanConfig) -> Iterator[SourceFile | ScanIssue]:
    try:
        size = path.stat().st_size
        if size > config.max_file_size_bytes:
            yield ScanIssue(
                level=IssueLevel.WARNING,
                source=_SOURCE,
                path=relative,
                message=f"skipped: file is larger than {config.max_file_size_bytes} bytes",
            )
            return
        data = path.read_bytes()
    except OSError:
        yield ScanIssue(
            level=IssueLevel.WARNING,
            source=_SOURCE,
            path=relative,
            message="skipped: file could not be read",
        )
        return

    if b"\x00" in data[:_BINARY_SNIFF_BYTES]:
        return  # binary file: nothing a text analyzer can do with it

    text = data.decode("utf-8-sig", errors="replace")
    yield SourceFile.from_text(relative, text)

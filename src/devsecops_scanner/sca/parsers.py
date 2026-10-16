"""Manifest and lock-file parsers.

Only *exact* versions are checked. A range such as ``requests>=2.0`` does not say which
version is installed, so reporting on it would produce either false alarms or false
reassurance. Such entries are counted and surfaced as a coverage warning instead.
"""

from __future__ import annotations

import fnmatch
import json
import re
from abc import ABC, abstractmethod
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import PurePosixPath
from typing import Any, Final

from devsecops_scanner.core.errors import FileAnalysisError
from devsecops_scanner.core.filesystem import SourceFile
from devsecops_scanner.core.models import Location
from devsecops_scanner.sca.models import Dependency, Ecosystem

_MAX_NESTING: Final = 64


@dataclass(frozen=True, slots=True)
class ParseResult:
    """Dependencies found in one file, plus the number of entries that could not be checked."""

    dependencies: tuple[Dependency, ...]
    unchecked: int = 0


class ManifestParser(ABC):
    """Extracts dependencies from one kind of file."""

    @abstractmethod
    def matches(self, path: str) -> bool:
        """Return ``True`` when this parser understands the file at ``path``."""

    @abstractmethod
    def parse(self, source: SourceFile) -> ParseResult:
        """Parse the file. Raise ``FileAnalysisError`` when it is malformed."""


# --------------------------------------------------------------------------------------
# requirements.txt
# --------------------------------------------------------------------------------------

_REQUIREMENT: Final = re.compile(
    r"^(?P<name>[A-Za-z0-9][A-Za-z0-9._-]{0,212})\s*"
    r"(?:\[[^\]]*\])?\s*"
    r"(?:===|==)\s*"
    r"(?P<version>[A-Za-z0-9][A-Za-z0-9.+!_-]{0,126})$"
)
_INLINE_COMMENT: Final = re.compile(r"(?:^|\s)#.*$")
_OPTION_TAIL: Final = re.compile(r"\s+--")


class RequirementsTxtParser(ManifestParser):
    """``requirements*.txt``: exact pins (``==`` / ``===``) are checked."""

    def matches(self, path: str) -> bool:
        return fnmatch.fnmatchcase(PurePosixPath(path).name.lower(), "*requirements*.txt")

    def parse(self, source: SourceFile) -> ParseResult:
        dependencies: list[Dependency] = []
        unchecked = 0

        for line_number, logical in _logical_lines(source.lines):
            text = _INLINE_COMMENT.sub("", logical).strip()
            if not text or text.startswith("-"):
                continue  # blank, comment or an option (-r, -e, --index-url, ...)

            # Drop the environment marker (``; python_version < "3.12"``) and per-requirement
            # options such as ``--hash=sha256:...``.
            text = text.split(";", 1)[0]
            text = _OPTION_TAIL.split(text, maxsplit=1)[0].strip()

            match = _REQUIREMENT.match(text)
            if match is None:
                unchecked += 1
                continue
            dependencies.append(
                Dependency(
                    name=match.group("name"),
                    version=match.group("version"),
                    ecosystem=Ecosystem.PYPI,
                    location=Location(path=source.path, line=line_number),
                )
            )
        return ParseResult(tuple(dependencies), unchecked)


def _logical_lines(lines: tuple[str, ...]) -> Iterator[tuple[int, str]]:
    """Join backslash-continued lines, yielding ``(first_line_number, text)``."""
    buffer: list[str] = []
    start = 1
    for number, raw in enumerate(lines, start=1):
        text = raw.rstrip()
        if not buffer:
            start = number
        if text.endswith("\\"):
            buffer.append(text[:-1])
            continue
        buffer.append(text)
        yield start, " ".join(buffer)
        buffer = []
    if buffer:
        yield start, " ".join(buffer)


# --------------------------------------------------------------------------------------
# package-lock.json
# --------------------------------------------------------------------------------------

_JSON_OBJECT_KEY: Final = re.compile(r'^[ \t]*"([^"\n]+)"[ \t]*:[ \t]*\{', re.MULTILINE)
_NODE_MODULES: Final = "node_modules/"


class PackageLockParser(ManifestParser):
    """npm ``package-lock.json`` (lockfile versions 1, 2 and 3)."""

    def matches(self, path: str) -> bool:
        return PurePosixPath(path).name == "package-lock.json"

    def parse(self, source: SourceFile) -> ParseResult:
        try:
            data: Any = json.loads(source.text)
        except (json.JSONDecodeError, RecursionError) as exc:
            raise FileAnalysisError(
                "package-lock.json is not valid JSON; file not analyzed"
            ) from exc
        if not isinstance(data, dict):
            raise FileAnalysisError("package-lock.json has an unexpected structure; not analyzed")

        key_lines = _index_key_lines(source.text)
        found: dict[tuple[str, str], Dependency] = {}

        packages = data.get("packages")
        if isinstance(packages, dict):
            for key, entry in packages.items():
                _add_from_packages_entry(source.path, key, entry, key_lines, found)
        else:
            legacy = data.get("dependencies")
            if isinstance(legacy, dict):
                _walk_legacy(source.path, legacy, key_lines, found, depth=0)

        return ParseResult(tuple(found.values()))


def _index_key_lines(text: str) -> dict[str, int]:
    """Map each JSON object key to the line of its first occurrence, in one linear pass."""
    index: dict[str, int] = {}
    line = 1
    last = 0
    for match in _JSON_OBJECT_KEY.finditer(text):
        line += text.count("\n", last, match.start())
        last = match.start()
        index.setdefault(match.group(1), line)
    return index


def _add_from_packages_entry(
    path: str,
    key: object,
    entry: object,
    key_lines: dict[str, int],
    found: dict[tuple[str, str], Dependency],
) -> None:
    if not isinstance(key, str) or not isinstance(entry, dict):
        return
    if _NODE_MODULES not in key or entry.get("link") is True:
        return  # the root project, a workspace or a symlink: not a registry package
    derived_name = key.rpartition(_NODE_MODULES)[2]
    real_name = entry.get("name")
    name = real_name if isinstance(real_name, str) and real_name else derived_name
    version = entry.get("version")
    if not name or not isinstance(version, str) or not version:
        return
    _remember(path, name, version, key_lines.get(key, 1), found)


def _walk_legacy(
    path: str,
    mapping: dict[str, Any],
    key_lines: dict[str, int],
    found: dict[tuple[str, str], Dependency],
    *,
    depth: int,
) -> None:
    if depth > _MAX_NESTING:
        return
    for name, entry in mapping.items():
        if not isinstance(entry, dict):
            continue
        version = entry.get("version")
        if isinstance(version, str) and version:
            _remember(path, name, version, key_lines.get(name, 1), found)
        nested = entry.get("dependencies")
        if isinstance(nested, dict):
            _walk_legacy(path, nested, key_lines, found, depth=depth + 1)


def _remember(
    path: str,
    name: str,
    version: str,
    line: int,
    found: dict[tuple[str, str], Dependency],
) -> None:
    if len(name) > 214 or len(version) > 128:
        return
    found.setdefault(
        (name, version),
        Dependency(
            name=name,
            version=version,
            ecosystem=Ecosystem.NPM,
            location=Location(path=path, line=line),
        ),
    )


DEFAULT_PARSERS: tuple[ManifestParser, ...] = (RequirementsTxtParser(), PackageLockParser())

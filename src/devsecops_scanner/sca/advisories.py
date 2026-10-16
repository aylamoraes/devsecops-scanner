"""Advisory database: loading, validation and lookup.

The bundled database is a *small, curated sample* meant for demonstration and testing.
It is not a substitute for a live feed (OSV, GitHub Advisory Database). The
:class:`AdvisoryDatabase` only needs ``Advisory`` objects, so a live source can be
plugged in by writing another loader; nothing else changes.
"""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Iterable
from importlib import resources
from pathlib import Path
from typing import Final, Literal

from pydantic import ValidationError

from devsecops_scanner.core.errors import AdvisoryDataError
from devsecops_scanner.core.models import FrozenModel
from devsecops_scanner.sca.models import Advisory, Ecosystem, normalize_name

_MAX_DATABASE_BYTES: Final = 20 * 1024 * 1024


class _AdvisoryFile(FrozenModel):
    schema_version: Literal[1]
    note: str | None = None
    advisories: tuple[Advisory, ...]


def load_advisories(path: Path | None = None) -> tuple[Advisory, ...]:
    """Load advisories from ``path``, or from the bundled sample when ``path`` is ``None``."""
    try:
        if path is None:
            resource = resources.files("devsecops_scanner.sca").joinpath("data")
            raw = resource.joinpath("advisories.json").read_text(encoding="utf-8")
        else:
            if path.stat().st_size > _MAX_DATABASE_BYTES:
                raise AdvisoryDataError("advisory database is too large")
            raw = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        raise AdvisoryDataError("advisory database could not be read") from exc

    try:
        parsed = _AdvisoryFile.model_validate_json(raw)
    except ValidationError as exc:
        # Locations and reasons only: never echo values from the file.
        details = "; ".join(
            f"{'.'.join(str(part) for part in err['loc'])}: {err['msg']}"
            for err in exc.errors(include_input=False)[:5]
        )
        raise AdvisoryDataError(f"advisory database failed validation: {details}") from exc

    seen: set[str] = set()
    for advisory in parsed.advisories:
        if advisory.id in seen:
            raise AdvisoryDataError("advisory database contains duplicate ids")
        seen.add(advisory.id)
    return parsed.advisories


class AdvisoryDatabase:
    """In-memory index of advisories by ``(ecosystem, normalized package name)``."""

    def __init__(self, advisories: Iterable[Advisory]) -> None:
        self._all: tuple[Advisory, ...] = tuple(advisories)
        index: defaultdict[tuple[Ecosystem, str], list[Advisory]] = defaultdict(list)
        for advisory in self._all:
            key = (advisory.ecosystem, normalize_name(advisory.ecosystem, advisory.package))
            index[key].append(advisory)
        self._index = dict(index)

    def lookup(self, ecosystem: Ecosystem, name: str) -> tuple[Advisory, ...]:
        """Return the advisories for a package (empty when there are none)."""
        return tuple(self._index.get((ecosystem, normalize_name(ecosystem, name)), ()))

    def advisories(self) -> tuple[Advisory, ...]:
        """Every advisory in the database."""
        return self._all

    def __len__(self) -> int:
        return len(self._all)

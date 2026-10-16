"""SCA domain models: dependencies, advisories and affected version ranges."""

from __future__ import annotations

from enum import StrEnum

from packaging.utils import canonicalize_name
from packaging.version import InvalidVersion, Version
from pydantic import Field, field_validator

from devsecops_scanner.core.models import FrozenModel, Location, Severity


class Ecosystem(StrEnum):
    """Package ecosystems, named as in the OSV schema."""

    PYPI = "PyPI"
    NPM = "npm"


def normalize_name(ecosystem: Ecosystem, name: str) -> str:
    """Normalize a package name so ``Requests``, ``requests`` and ``PyYAML``/``pyyaml`` match.

    PyPI names follow PEP 503 (case-insensitive; ``-``, ``_`` and ``.`` are equivalent).
    npm names are lowercase by registry rule.
    """
    if ecosystem is Ecosystem.PYPI:
        return str(canonicalize_name(name))
    return name.lower()


class Dependency(FrozenModel):
    """A dependency declared (and pinned) in a manifest or lock file."""

    name: str = Field(min_length=1, max_length=214)
    version: str = Field(min_length=1, max_length=128)
    ecosystem: Ecosystem
    location: Location


class VersionRange(FrozenModel):
    """Half-open interval ``[introduced, fixed)``, as in the OSV schema.

    ``introduced=None`` means "since the first release"; ``fixed=None`` means "no fix yet".
    """

    introduced: str | None = None
    fixed: str | None = None

    @field_validator("introduced", "fixed")
    @classmethod
    def _must_be_a_version(cls, value: str | None) -> str | None:
        if value is not None:
            try:
                Version(value)
            except InvalidVersion as exc:
                raise ValueError("not a valid version") from exc
        return value

    def contains(self, version: Version) -> bool:
        """Return ``True`` when ``version`` falls inside the interval."""
        if self.introduced is not None and version < Version(self.introduced):
            return False
        return self.fixed is None or version < Version(self.fixed)


class Advisory(FrozenModel):
    """A known vulnerability affecting one package."""

    id: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]*$", max_length=100)
    ecosystem: Ecosystem
    package: str = Field(min_length=1, max_length=214)
    ranges: tuple[VersionRange, ...] = Field(min_length=1)
    severity: Severity
    summary: str = Field(min_length=1, max_length=300)
    cvss: float | None = Field(default=None, ge=0, le=10)
    cwe: str | None = Field(default=None, pattern=r"^CWE-\d{1,5}$")
    references: tuple[str, ...] = ()

    def matching_range(self, version: Version) -> VersionRange | None:
        """Return the first affected range that contains ``version``, if any."""
        for candidate in self.ranges:
            if candidate.contains(version):
                return candidate
        return None

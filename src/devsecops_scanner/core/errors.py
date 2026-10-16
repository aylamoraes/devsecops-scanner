"""Exception hierarchy.

Error messages must never echo untrusted values (file contents, secrets): they end
up in CI logs and in reports that may be uploaded as build artifacts.
"""

from __future__ import annotations


class ScannerError(Exception):
    """Base class for every error raised deliberately by this package."""


class ConfigError(ScannerError):
    """The configuration file or the command-line options are invalid."""


class AdvisoryDataError(ScannerError):
    """The advisory database could not be read or failed validation."""


class FileAnalysisError(ScannerError):
    """Raised by an analyzer for an expected, non-fatal problem with one file.

    Example: a Python file with a syntax error cannot be parsed. The engine turns
    this into a warning issue and moves on to the next file.
    """

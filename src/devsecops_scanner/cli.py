"""Command-line interface (``dsscan``).

Exit codes, designed for CI:

* ``0``: scan completed, nothing at or above the ``--fail-on`` threshold.
* ``1``: scan completed, at least one finding at or above the threshold.
* ``2``: usage or configuration error, or an analyzer crashed (results are incomplete).
  A broken scan must never look like a clean one, so errors win over findings.
"""

from __future__ import annotations

import argparse
import contextlib
import io
import os
import sys
from collections.abc import Sequence
from pathlib import Path
from typing import Any, Final

from pydantic import ValidationError

from devsecops_scanner import __version__
from devsecops_scanner.bootstrap import build_analyzers, build_engine
from devsecops_scanner.core.config import AnalyzerName, ScanConfig, load_config
from devsecops_scanner.core.errors import ConfigError, ScannerError
from devsecops_scanner.core.models import Severity
from devsecops_scanner.reporting import REPORTER_NAMES, get_reporter

EXIT_OK: Final = 0
EXIT_FINDINGS: Final = 1
EXIT_ERROR: Final = 2

_FAIL_ON_CHOICES: Final = ("none", *(severity.value for severity in reversed(list(Severity))))
_ANALYZER_CHOICES: Final = tuple(name.value for name in AnalyzerName)


def build_parser() -> argparse.ArgumentParser:
    """Create the argument parser."""
    parser = argparse.ArgumentParser(
        prog="dsscan",
        description="SAST, SCA and secret detection for CI/CD pipelines.",
        epilog="Exit codes: 0 = clean, 1 = findings at/above --fail-on, 2 = error.",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    commands = parser.add_subparsers(dest="command", required=True)

    scan = commands.add_parser("scan", help="scan a directory or a single file")
    scan.add_argument("path", nargs="?", default=Path("."), type=Path, help="default: .")
    scan.add_argument("-f", "--format", choices=REPORTER_NAMES, default="text")
    scan.add_argument("-o", "--output", type=Path, help="write the report to a file")
    scan.add_argument(
        "--fail-on",
        choices=_FAIL_ON_CHOICES,
        help="lowest severity that makes the exit code 1 (default: high, or the config file)",
    )
    scan.add_argument("--config", type=Path, help="path to a .dsscan.toml file")
    scan.add_argument(
        "--only",
        action="append",
        choices=_ANALYZER_CHOICES,
        help="run only this analyzer (repeatable)",
    )
    scan.add_argument(
        "--exclude",
        action="append",
        default=[],
        metavar="PATTERN",
        help="glob pattern to skip (repeatable)",
    )
    scan.add_argument("--advisories", type=Path, help="advisory database (JSON) for SCA")

    commands.add_parser("rules", help="list the built-in rules")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """Entry point. Returns the process exit code."""
    _make_output_safe()
    args = build_parser().parse_args(argv)
    try:
        if args.command == "scan":
            return _scan(args)
        return _list_rules()
    except ScannerError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_ERROR
    except BrokenPipeError:
        # The reader closed the pipe early (``dsscan rules | head``). That is not a bug
        # in the scanner, so there must be no traceback. For ``scan`` the report was not
        # delivered, so the run is reported as failed (fail closed), never as clean.
        _silence_stdout()
        return EXIT_ERROR if args.command == "scan" else EXIT_OK


def _scan(args: argparse.Namespace) -> int:
    root: Path = args.path
    if not root.exists():
        raise ConfigError("scan path does not exist")

    config = _effective_config(args, root)
    result = build_engine(config).scan(root, config)
    _emit(get_reporter(args.format).render(result), args.output)

    if result.has_errors:
        return EXIT_ERROR
    return EXIT_FINDINGS if result.exceeds(config.fail_on) else EXIT_OK


def _effective_config(args: argparse.Namespace, root: Path) -> ScanConfig:
    """Merge defaults, the config file and command-line flags (flags win)."""
    base = load_config(args.config, root=root)

    overrides: dict[str, Any] = {}
    if args.fail_on is not None:
        overrides["fail_on"] = args.fail_on
    if args.only:
        overrides["analyzers"] = frozenset(AnalyzerName(value) for value in args.only)
    if args.exclude:
        overrides["exclude"] = (*base.exclude, *args.exclude)
    if args.advisories is not None:
        overrides["advisories_path"] = args.advisories
    if not overrides:
        return base

    try:
        return ScanConfig.model_validate({**base.model_dump(), **overrides})
    except ValidationError as exc:
        raise ConfigError("invalid command-line options") from exc


def _list_rules() -> int:
    print(f"{'RULE':<32} {'SEVERITY':<9} {'ENGINE':<7} TITLE")
    for analyzer in build_analyzers(ScanConfig()):
        for rule in analyzer.rules():
            print(f"{rule.rule_id:<32} {rule.severity.value:<9} {rule.kind.value:<7} {rule.title}")
    return EXIT_OK


def _emit(report: str, output: Path | None) -> None:
    if output is None:
        sys.stdout.write(report)
        return
    try:
        output.write_text(report, encoding="utf-8")
    except OSError as exc:
        raise ConfigError("report could not be written") from exc
    print(f"report written to {output}", file=sys.stderr)


def _make_output_safe() -> None:
    """Never crash on characters the console cannot encode (common on Windows)."""
    for stream in (sys.stdout, sys.stderr):
        if isinstance(stream, io.TextIOWrapper):
            with contextlib.suppress(ValueError, OSError):
                stream.reconfigure(errors="replace")


def _silence_stdout() -> None:
    """Point stdout at the null device so the interpreter's exit flush cannot fail again."""
    with contextlib.suppress(OSError, ValueError):
        devnull = os.open(os.devnull, os.O_WRONLY)
        os.dup2(devnull, sys.stdout.fileno())

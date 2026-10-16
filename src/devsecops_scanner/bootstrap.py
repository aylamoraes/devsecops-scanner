"""Composition root: the only module that knows every concrete analyzer.

Everything else depends on abstractions, so this is the single place where the
object graph is assembled (Dependency Injection, as in the Mini-SOAR project).
"""

from __future__ import annotations

from devsecops_scanner.core.analyzer import Analyzer
from devsecops_scanner.core.config import AnalyzerName, ScanConfig
from devsecops_scanner.core.engine import ScanEngine
from devsecops_scanner.sast import SastAnalyzer
from devsecops_scanner.sca import AdvisoryDatabase, ScaAnalyzer, load_advisories
from devsecops_scanner.secret_detection import SecretAnalyzer


def build_analyzers(config: ScanConfig) -> list[Analyzer]:
    """Create the analyzers enabled by ``config``."""
    analyzers: list[Analyzer] = []
    if AnalyzerName.SAST in config.analyzers:
        analyzers.append(SastAnalyzer())
    if AnalyzerName.SECRETS in config.analyzers:
        analyzers.append(SecretAnalyzer())
    if AnalyzerName.SCA in config.analyzers:
        database = AdvisoryDatabase(load_advisories(config.advisories_path))
        analyzers.append(ScaAnalyzer(database))
    return analyzers


def build_engine(config: ScanConfig) -> ScanEngine:
    """Create a ready-to-use :class:`ScanEngine`."""
    return ScanEngine(build_analyzers(config))

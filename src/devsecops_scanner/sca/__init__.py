"""Software composition analysis (SCA): known-vulnerable dependencies."""

from devsecops_scanner.sca.advisories import AdvisoryDatabase, load_advisories
from devsecops_scanner.sca.analyzer import ScaAnalyzer

__all__ = ["AdvisoryDatabase", "ScaAnalyzer", "load_advisories"]

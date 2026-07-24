"""
Vulnerability Research

Automated vulnerability discovery and analysis for AI-RedTeaming.
"""

from .cve_database import CVEDatabase
from .exploit_finder import ExploitFinder
from .patch_analyzer import PatchAnalyzer
from .fuzzer import Fuzzer
from .zero_day import ZeroDayResearcher

__all__ = [
    'CVEDatabase',
    'ExploitFinder',
    'PatchAnalyzer',
    'Fuzzer',
    'ZeroDayResearcher'
]

"""
Dependency scanner module — detects and parses third-party dependencies
from various package manager formats.
"""

from nvd_checker.scanner.base import Dependency, DependencyParser
from nvd_checker.scanner.detector import DependencyDetector

__all__ = ["Dependency", "DependencyParser", "DependencyDetector"]

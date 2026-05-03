"""
NVD Checker — CLI tool to scan repositories for vulnerable dependencies.

Scans Git repositories to detect third-party libraries, queries the NVD
(National Vulnerability Database) API 2.0 for known CVEs, and generates
detailed reports with remediation tips.
"""

__version__ = "1.0.0"
__all__ = ["__version__"]

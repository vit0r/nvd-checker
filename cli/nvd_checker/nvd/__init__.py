"""
NVD API module — client, models, and matching logic for the
National Vulnerability Database API 2.0.
"""

from nvd_checker.nvd.client import NVDClient
from nvd_checker.nvd.matcher import VulnerabilityMatcher
from nvd_checker.nvd.models import CVERecord, CVSSScore

__all__ = ["NVDClient", "VulnerabilityMatcher", "CVERecord", "CVSSScore"]

"""
Tests for the vulnerability matcher.
"""

import pytest

from nvd_checker.nvd.matcher import VulnerabilityMatcher, VulnerabilityResult
from nvd_checker.nvd.models import CVERecord, CVSSScore, CPEMatch
from nvd_checker.scanner.base import Dependency


class FakeNVDClient:
    """Fake NVD client that returns predefined results."""

    def __init__(self, cves=None):
        self.cves = cves or []

    def search_by_keyword(self, keyword, results_per_page=50):
        return self.cves

    def search_by_cpe(self, cpe_name, is_vulnerable=True):
        return self.cves

    def get_cve(self, cve_id):
        for cve in self.cves:
            if cve.cve_id == cve_id:
                return cve
        return None


def _make_cve(cve_id, score=7.0, severity="HIGH", description="test vuln",
              cpe_name="", version_end=""):
    """Helper to create a CVERecord."""
    cve = CVERecord(
        cve_id=cve_id,
        description=description,
        cvss=CVSSScore(base_score=score, base_severity=severity),
    )
    if cpe_name:
        cve.cpe_matches.append(
            CPEMatch(
                cpe_name=cpe_name,
                vulnerable=True,
                version_end=version_end,
                version_end_type="excluding" if version_end else "",
            )
        )
    return cve


class TestVulnerabilityMatcher:
    def test_vulnerable_dependency(self):
        cve = _make_cve(
            "CVE-2023-0001",
            description="Vulnerability in requests library",
            cpe_name="cpe:2.3:a:python:requests:*",
            version_end="2.29.0",
        )
        client = FakeNVDClient(cves=[cve])
        matcher = VulnerabilityMatcher(client)

        dep = Dependency(name="requests", version="2.28.0", ecosystem="python")
        result = matcher.check_dependency(dep)

        assert result.is_vulnerable
        assert len(result.cves) == 1
        assert result.max_severity == "HIGH"

    def test_safe_dependency(self):
        cve = _make_cve(
            "CVE-2023-0001",
            description="Vulnerability in requests library",
            cpe_name="cpe:2.3:a:python:requests:*",
            version_end="2.28.0",
        )
        client = FakeNVDClient(cves=[cve])
        matcher = VulnerabilityMatcher(client)

        # Version is at the boundary (excluding), so it's safe
        dep = Dependency(name="requests", version="2.28.0", ecosystem="python")
        result = matcher.check_dependency(dep)

        # version_end=2.28.0 with type=excluding means <2.28.0 is affected
        # 2.28.0 is NOT affected
        assert not result.is_vulnerable

    def test_no_cves_found(self):
        client = FakeNVDClient(cves=[])
        matcher = VulnerabilityMatcher(client)

        dep = Dependency(name="safe-lib", version="1.0.0", ecosystem="python")
        result = matcher.check_dependency(dep)

        assert not result.is_vulnerable
        assert result.max_severity == "NONE"

    def test_caching(self):
        cve = _make_cve("CVE-2023-0001", description="test requests vuln")
        client = FakeNVDClient(cves=[cve])
        matcher = VulnerabilityMatcher(client)

        dep1 = Dependency(name="requests", version="2.28.0", ecosystem="python")
        dep2 = Dependency(name="requests", version="2.28.0", ecosystem="python")

        matcher.check_dependency(dep1)
        matcher.check_dependency(dep2)

        # Should use cache for the second call
        assert "requests:python" in matcher._cache


class TestVulnerabilityResult:
    def test_max_severity_with_multiple_cves(self):
        dep = Dependency(name="test", version="1.0", ecosystem="python")
        result = VulnerabilityResult(
            dependency=dep,
            cves=[
                _make_cve("CVE-1", score=3.0, severity="LOW"),
                _make_cve("CVE-2", score=9.8, severity="CRITICAL"),
                _make_cve("CVE-3", score=5.0, severity="MEDIUM"),
            ],
        )

        assert result.max_severity == "CRITICAL"
        assert result.max_score == 9.8
        assert result.is_vulnerable

    def test_empty_result(self):
        dep = Dependency(name="test", version="1.0", ecosystem="python")
        result = VulnerabilityResult(dependency=dep)

        assert not result.is_vulnerable
        assert result.max_severity == "NONE"
        assert result.max_score == 0.0

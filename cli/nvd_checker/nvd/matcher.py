"""
Vulnerability matcher — correlates project dependencies with known
CVEs from the NVD database.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field

from packaging.version import Version, InvalidVersion

from nvd_checker.nvd.client import NVDClient
from nvd_checker.nvd.models import CVERecord, CPEMatch
from nvd_checker.scanner.base import Dependency

logger = logging.getLogger("nvd_checker")


@dataclass
class VulnerabilityResult:
    """Vulnerability check result for a single dependency."""
    dependency: Dependency
    cves: list[CVERecord] = field(default_factory=list)
    error: str | None = None

    @property
    def is_vulnerable(self) -> bool:
        return len(self.cves) > 0

    @property
    def max_severity(self) -> str:
        if not self.cves:
            return "NONE"
        order = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "NONE": 0}
        return max(self.cves, key=lambda c: order.get(c.severity, 0)).severity

    @property
    def max_score(self) -> float:
        if not self.cves:
            return 0.0
        return max(c.score for c in self.cves)


class VulnerabilityMatcher:
    """Matches dependencies against NVD CVE records.

    Uses keyword search as the primary strategy, then filters results
    by checking CPE version ranges against the dependency version.
    """

    def __init__(self, client: NVDClient) -> None:
        self.client = client
        self._cache: dict[str, list[CVERecord]] = {}

    def check_dependency(self, dep: Dependency) -> VulnerabilityResult:
        """Check a single dependency for known vulnerabilities."""
        result = VulnerabilityResult(dependency=dep)

        if not dep.name:
            return result

        try:
            cache_key = f"{dep.name}:{dep.ecosystem}"
            if cache_key in self._cache:
                all_cves = self._cache[cache_key]
            else:
                all_cves = self._search_cves(dep)
                self._cache[cache_key] = all_cves

            # Filter CVEs by version if we have version info
            if dep.version and all_cves:
                result.cves = self._filter_by_version(all_cves, dep)
            else:
                result.cves = all_cves

        except Exception as e:
            result.error = str(e)
            logger.warning(f"Error checking {dep.display_name}: {e}")

        return result

    def check_dependencies(
        self, deps: list[Dependency]
    ) -> list[VulnerabilityResult]:
        """Check multiple dependencies for vulnerabilities."""
        results: list[VulnerabilityResult] = []
        for i, dep in enumerate(deps, 1):
            logger.info(
                f"  [{i}/{len(deps)}] Checking {dep.display_name}..."
            )
            result = self.check_dependency(dep)
            results.append(result)
            if result.is_vulnerable:
                logger.info(
                    f"    ⚠ Found {len(result.cves)} CVE(s) "
                    f"(max severity: {result.max_severity})"
                )
        return results

    def _search_cves(self, dep: Dependency) -> list[CVERecord]:
        """Search for CVEs related to a dependency."""
        keyword = dep.name
        logger.debug(f"  Searching NVD for keyword: {keyword}")
        cves = self.client.search_by_keyword(keyword, results_per_page=50)

        # Filter to keep only CVEs that mention the package name
        # in their description or CPE matches
        name_lower = dep.name.lower().replace("-", "").replace("_", "")
        filtered = []
        for cve in cves:
            desc_lower = cve.description.lower().replace("-", "").replace("_", "")
            cpe_match = any(
                name_lower in m.cpe_name.lower().replace("-", "").replace("_", "")
                for m in cve.cpe_matches
            )
            if name_lower in desc_lower or cpe_match:
                filtered.append(cve)

        return filtered

    def _filter_by_version(
        self, cves: list[CVERecord], dep: Dependency
    ) -> list[CVERecord]:
        """Filter CVEs to only those affecting the dependency's version."""
        if not dep.version:
            return cves

        matching: list[CVERecord] = []

        try:
            dep_version = Version(dep.version)
        except InvalidVersion:
            # If we can't parse the version, return all CVEs as potential matches
            return cves

        for cve in cves:
            if self._version_affected(cve, dep_version, dep.name):
                matching.append(cve)

        return matching

    def _version_affected(
        self, cve: CVERecord, dep_version: Version, dep_name: str
    ) -> bool:
        """Check if a specific version is affected by a CVE."""
        name_lower = dep_name.lower().replace("-", "").replace("_", "")

        # Check CPE matches for version ranges
        relevant_matches = [
            m for m in cve.cpe_matches
            if m.vulnerable and
            name_lower in m.cpe_name.lower().replace("-", "").replace("_", "")
        ]

        if not relevant_matches:
            # No CPE data — include if CVE mentions the name
            # (conservative approach)
            return True

        for match in relevant_matches:
            if self._version_in_range(dep_version, match):
                return True

        return False

    @staticmethod
    def _version_in_range(version: Version, match: CPEMatch) -> bool:
        """Check if a version falls within a CPE match range."""
        try:
            # Check start bound
            if match.version_start:
                try:
                    start = Version(match.version_start)
                    if match.version_start_type == "including":
                        if version < start:
                            return False
                    elif match.version_start_type == "excluding":
                        if version <= start:
                            return False
                except InvalidVersion:
                    pass

            # Check end bound
            if match.version_end:
                try:
                    end = Version(match.version_end)
                    if match.version_end_type == "including":
                        if version > end:
                            return False
                    elif match.version_end_type == "excluding":
                        if version >= end:
                            return False
                except InvalidVersion:
                    pass

            return True

        except Exception:
            return True  # Conservative: include on error

"""
Data models for NVD API 2.0 responses — typed dataclasses for
CVE records, CVSS scores, and related structures.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class CVSSScore:
    """CVSS score information."""
    version: str = ""
    vector_string: str = ""
    base_score: float = 0.0
    base_severity: str = "NONE"
    exploitability_score: float = 0.0
    impact_score: float = 0.0

    @property
    def severity_emoji(self) -> str:
        emojis = {
            "CRITICAL": "🔴", "HIGH": "🟠",
            "MEDIUM": "🟡", "LOW": "🟢", "NONE": "⚪",
        }
        return emojis.get(self.base_severity.upper(), "⚪")


@dataclass
class Weakness:
    """CWE weakness information."""
    cwe_id: str = ""
    description: str = ""


@dataclass
class Reference:
    """External reference/link for a CVE."""
    url: str = ""
    source: str = ""
    tags: list[str] = field(default_factory=list)


@dataclass
class CPEMatch:
    """CPE match criteria for affected products."""
    cpe_name: str = ""
    vulnerable: bool = False
    version_start: str = ""
    version_start_type: str = ""  # "including" or "excluding"
    version_end: str = ""
    version_end_type: str = ""


@dataclass
class CVERecord:
    """A single CVE vulnerability record from the NVD."""
    cve_id: str = ""
    description: str = ""
    published: str = ""
    last_modified: str = ""
    cvss: CVSSScore = field(default_factory=CVSSScore)
    weaknesses: list[Weakness] = field(default_factory=list)
    references: list[Reference] = field(default_factory=list)
    cpe_matches: list[CPEMatch] = field(default_factory=list)
    source_identifier: str = ""

    @property
    def severity(self) -> str:
        return self.cvss.base_severity.upper() or "UNKNOWN"

    @property
    def score(self) -> float:
        return self.cvss.base_score

    @property
    def nvd_url(self) -> str:
        return f"https://nvd.nist.gov/vuln/detail/{self.cve_id}"

    @property
    def primary_cwe(self) -> str:
        if self.weaknesses:
            return self.weaknesses[0].cwe_id
        return "N/A"

    @classmethod
    def from_api_response(cls, vuln_data: dict) -> CVERecord:
        """Parse a single vulnerability item from the NVD API response."""
        cve = vuln_data.get("cve", {})
        record = cls(
            cve_id=cve.get("id", ""),
            source_identifier=cve.get("sourceIdentifier", ""),
            published=cve.get("published", ""),
            last_modified=cve.get("lastModified", ""),
        )

        # Description (English preferred)
        for desc in cve.get("descriptions", []):
            if desc.get("lang") == "en":
                record.description = desc.get("value", "")
                break
        if not record.description:
            descs = cve.get("descriptions", [])
            if descs:
                record.description = descs[0].get("value", "")

        # CVSS scores — prefer v3.1, then v4.0, then v2.0
        metrics = cve.get("metrics", {})
        record.cvss = cls._parse_cvss(metrics)

        # Weaknesses
        for w in cve.get("weaknesses", []):
            for desc in w.get("description", []):
                record.weaknesses.append(
                    Weakness(cwe_id=desc.get("value", ""), description="")
                )

        # References
        for ref in cve.get("references", []):
            record.references.append(
                Reference(
                    url=ref.get("url", ""),
                    source=ref.get("source", ""),
                    tags=ref.get("tags", []),
                )
            )

        # CPE Matches
        for config in cve.get("configurations", []):
            for node in config.get("nodes", []):
                for match in node.get("cpeMatch", []):
                    record.cpe_matches.append(
                        CPEMatch(
                            cpe_name=match.get("criteria", ""),
                            vulnerable=match.get("vulnerable", False),
                            version_start=match.get("versionStartIncluding", "")
                            or match.get("versionStartExcluding", ""),
                            version_start_type=(
                                "including" if match.get("versionStartIncluding")
                                else "excluding" if match.get("versionStartExcluding")
                                else ""
                            ),
                            version_end=match.get("versionEndIncluding", "")
                            or match.get("versionEndExcluding", ""),
                            version_end_type=(
                                "including" if match.get("versionEndIncluding")
                                else "excluding" if match.get("versionEndExcluding")
                                else ""
                            ),
                        )
                    )

        return record

    @staticmethod
    def _parse_cvss(metrics: dict) -> CVSSScore:
        """Extract the best available CVSS score."""
        # Try CVSS v3.1
        for m in metrics.get("cvssMetricV31", []):
            d = m.get("cvssData", {})
            return CVSSScore(
                version="3.1", vector_string=d.get("vectorString", ""),
                base_score=d.get("baseScore", 0.0),
                base_severity=d.get("baseSeverity", "NONE"),
                exploitability_score=m.get("exploitabilityScore", 0.0),
                impact_score=m.get("impactScore", 0.0),
            )
        # Try CVSS v4.0
        for m in metrics.get("cvssMetricV40", []):
            d = m.get("cvssData", {})
            return CVSSScore(
                version="4.0", vector_string=d.get("vectorString", ""),
                base_score=d.get("baseScore", 0.0),
                base_severity=d.get("baseSeverity", "NONE"),
                exploitability_score=m.get("exploitabilityScore", 0.0),
                impact_score=m.get("impactScore", 0.0),
            )
        # Try CVSS v2.0
        for m in metrics.get("cvssMetricV2", []):
            d = m.get("cvssData", {})
            return CVSSScore(
                version="2.0", vector_string=d.get("vectorString", ""),
                base_score=d.get("baseScore", 0.0),
                base_severity=m.get("baseSeverity", "NONE"),
                exploitability_score=m.get("exploitabilityScore", 0.0),
                impact_score=m.get("impactScore", 0.0),
            )
        return CVSSScore()

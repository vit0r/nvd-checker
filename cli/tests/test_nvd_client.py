"""
Tests for the NVD API client (using mocked responses).
"""

import json

import pytest
import responses

from nvd_checker.nvd.client import NVDClient, NVD_API_BASE
from nvd_checker.nvd.models import CVERecord


def _make_nvd_response(cve_id="CVE-2023-0001", score=7.5, severity="HIGH"):
    """Create a minimal NVD API response."""
    return {
        "resultsPerPage": 1,
        "startIndex": 0,
        "totalResults": 1,
        "vulnerabilities": [
            {
                "cve": {
                    "id": cve_id,
                    "sourceIdentifier": "test@test.com",
                    "published": "2023-01-01T00:00:00.000",
                    "lastModified": "2023-06-01T00:00:00.000",
                    "descriptions": [
                        {"lang": "en", "value": "Test vulnerability description."}
                    ],
                    "metrics": {
                        "cvssMetricV31": [
                            {
                                "cvssData": {
                                    "version": "3.1",
                                    "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
                                    "baseScore": score,
                                    "baseSeverity": severity,
                                },
                                "exploitabilityScore": 3.9,
                                "impactScore": 3.6,
                            }
                        ]
                    },
                    "weaknesses": [
                        {
                            "description": [
                                {"lang": "en", "value": "CWE-79"}
                            ]
                        }
                    ],
                    "references": [
                        {
                            "url": "https://example.com/advisory",
                            "source": "test",
                            "tags": ["Vendor Advisory"],
                        }
                    ],
                    "configurations": [],
                }
            }
        ],
    }


class TestNVDClient:
    @responses.activate
    def test_search_by_keyword(self):
        responses.add(
            responses.GET,
            NVD_API_BASE,
            json=_make_nvd_response(),
            status=200,
        )

        client = NVDClient(rate_limit_delay=0)
        results = client.search_by_keyword("test")

        assert len(results) == 1
        assert results[0].cve_id == "CVE-2023-0001"
        assert results[0].score == 7.5
        assert results[0].severity == "HIGH"

    @responses.activate
    def test_get_cve(self):
        responses.add(
            responses.GET,
            NVD_API_BASE,
            json=_make_nvd_response(cve_id="CVE-2023-9999"),
            status=200,
        )

        client = NVDClient(rate_limit_delay=0)
        cve = client.get_cve("CVE-2023-9999")

        assert cve is not None
        assert cve.cve_id == "CVE-2023-9999"
        assert cve.primary_cwe == "CWE-79"

    @responses.activate
    def test_empty_response(self):
        responses.add(
            responses.GET,
            NVD_API_BASE,
            json={"resultsPerPage": 0, "startIndex": 0, "totalResults": 0, "vulnerabilities": []},
            status=200,
        )

        client = NVDClient(rate_limit_delay=0)
        results = client.search_by_keyword("nonexistent")
        assert len(results) == 0

    @responses.activate
    def test_api_key_header(self):
        responses.add(
            responses.GET,
            NVD_API_BASE,
            json=_make_nvd_response(),
            status=200,
        )

        client = NVDClient(api_key="test-key", rate_limit_delay=0)
        client.search_by_keyword("test")

        assert responses.calls[0].request.headers.get("apiKey") == "test-key"


class TestCVERecord:
    def test_from_api_response(self):
        data = _make_nvd_response()
        vuln = data["vulnerabilities"][0]
        record = CVERecord.from_api_response(vuln)

        assert record.cve_id == "CVE-2023-0001"
        assert record.description == "Test vulnerability description."
        assert record.cvss.version == "3.1"
        assert record.cvss.base_score == 7.5
        assert record.severity == "HIGH"
        assert record.nvd_url == "https://nvd.nist.gov/vuln/detail/CVE-2023-0001"
        assert len(record.references) == 1
        assert len(record.weaknesses) == 1

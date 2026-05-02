"""
Tests for the report generator and security advisor.
"""

import json
from pathlib import Path

import pytest

from nvd_checker.nvd.matcher import VulnerabilityResult
from nvd_checker.nvd.models import CVERecord, CVSSScore, Weakness
from nvd_checker.report.advisor import SecurityAdvisor
from nvd_checker.report.generator import ReportGenerator
from nvd_checker.scanner.base import Dependency, ScanResult


def _make_test_data():
    """Create test scan + vulnerability data."""
    dep = Dependency(name="requests", version="2.28.0", ecosystem="python",
                     source_file="requirements.txt")
    scan = ScanResult(
        repo_path="/tmp/test-repo",
        dependencies=[dep],
        files_scanned=["requirements.txt"],
    )

    cve = CVERecord(
        cve_id="CVE-2023-0001",
        description="Test vulnerability in requests library.",
        published="2023-01-15T00:00:00.000",
        cvss=CVSSScore(base_score=7.5, base_severity="HIGH", version="3.1"),
        weaknesses=[Weakness(cwe_id="CWE-79")],
    )

    vuln = VulnerabilityResult(dependency=dep, cves=[cve])
    return scan, [vuln]


class TestSecurityAdvisor:
    def test_get_advice_high(self):
        cve = CVERecord(
            cve_id="CVE-2023-0001",
            cvss=CVSSScore(base_score=8.5, base_severity="HIGH"),
            weaknesses=[Weakness(cwe_id="CWE-89")],
        )

        advisor = SecurityAdvisor()
        advice = advisor.get_advice(cve, "django")

        assert "HIGH" in advice["urgency"]
        assert len(advice["fix_steps"]) > 0
        assert "SQL Injection" in advice["cwe_guidance"]
        assert "django" in advice["update_recommendation"]

    def test_get_advice_critical(self):
        cve = CVERecord(
            cve_id="CVE-2023-9999",
            cvss=CVSSScore(base_score=9.8, base_severity="CRITICAL"),
        )

        advisor = SecurityAdvisor()
        advice = advisor.get_advice(cve, "log4j")

        assert "CRITICAL" in advice["urgency"]
        assert advice["cwe_guidance"] is None  # No CWE

    def test_get_advice_low(self):
        cve = CVERecord(
            cve_id="CVE-2023-0002",
            cvss=CVSSScore(base_score=2.0, base_severity="LOW"),
        )

        advisor = SecurityAdvisor()
        advice = advisor.get_advice(cve)

        assert "LOW" in advice["urgency"]


class TestReportGenerator:
    def test_severity_breakdown(self):
        scan, vulns = _make_test_data()
        report = ReportGenerator(scan, vulns)

        breakdown = report.severity_breakdown
        assert breakdown["HIGH"] == 1
        assert breakdown["CRITICAL"] == 0

    def test_total_cves(self):
        scan, vulns = _make_test_data()
        report = ReportGenerator(scan, vulns)
        assert report.total_cves == 1

    def test_vulnerable_results(self):
        scan, vulns = _make_test_data()
        report = ReportGenerator(scan, vulns)
        assert len(report.vulnerable_results) == 1

    def test_json_output(self, tmp_path):
        scan, vulns = _make_test_data()
        report = ReportGenerator(scan, vulns)

        output = tmp_path / "report.json"
        report.to_json(str(output))

        assert output.exists()
        data = json.loads(output.read_text())
        assert data["summary"]["total_cves"] == 1
        assert len(data["vulnerabilities"]) == 1
        assert data["vulnerabilities"][0]["cve_id"] == "CVE-2023-0001"

    def test_html_output(self, tmp_path):
        scan, vulns = _make_test_data()
        report = ReportGenerator(scan, vulns)

        output = tmp_path / "report.html"
        report.to_html(str(output))

        assert output.exists()
        content = output.read_text()
        assert "CVE-2023-0001" in content
        assert "requests" in content

    def test_terminal_output(self, capsys):
        scan, vulns = _make_test_data()
        report = ReportGenerator(scan, vulns)
        # Should not raise
        report.to_terminal()

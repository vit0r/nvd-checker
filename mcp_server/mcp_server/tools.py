"""
MCP Tools — exposes nvd-checker scanning capabilities as MCP tools.

Each tool wraps the internal nvd_checker Python API (no subprocess)
and returns structured results for the AI agent to interpret.
"""

from __future__ import annotations

import json
import logging
import os
from pathlib import Path
from typing import Annotated

from mcp_server.repo_manager import RepoManager
from nvd_checker.nvd.client import NVDClient
from nvd_checker.nvd.matcher import VulnerabilityMatcher, VulnerabilityResult
from nvd_checker.report.generator import ReportGenerator
from nvd_checker.scanner.base import Dependency, ScanResult
from nvd_checker.scanner.detector import DependencyDetector

logger = logging.getLogger("nvd_checker.mcp")

# Severity levels for filtering
SEVERITY_LEVELS = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}


def _get_api_key(api_key: str | None = None) -> str | None:
    """Resolve NVD API key from parameter or environment."""
    return api_key or os.getenv("NVD_API_KEY")


def _serialize_scan_result(scan_result: ScanResult) -> dict:
    """Convert ScanResult to a serializable dict."""
    return {
        "repo_path": scan_result.repo_path,
        "files_scanned": scan_result.files_scanned,
        "total_dependencies": scan_result.total_dependencies,
        "ecosystems": list(scan_result.ecosystems),
        "dependencies": [
            {
                "name": dep.name,
                "version": dep.version,
                "ecosystem": dep.ecosystem,
                "source_file": dep.source_file,
            }
            for dep in scan_result.dependencies
        ],
    }


def _serialize_vuln_results(
    vuln_results: list[VulnerabilityResult],
) -> list[dict]:
    """Convert vulnerability results to serializable dicts."""
    results = []
    for result in vuln_results:
        if not result.is_vulnerable:
            continue
        for cve in result.cves:
            results.append({
                "package": result.dependency.name,
                "version": result.dependency.version,
                "ecosystem": result.dependency.ecosystem,
                "cve_id": cve.cve_id,
                "description": cve.description,
                "score": cve.score,
                "severity": cve.severity,
                "cwe": cve.primary_cwe,
                "published": cve.published,
                "nvd_url": cve.nvd_url,
                "cvss_vector": cve.cvss.vector_string,
            })
    return results


def _severity_breakdown(vuln_results: list[VulnerabilityResult]) -> dict:
    """Compute severity breakdown from results."""
    breakdown = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for result in vuln_results:
        for cve in result.cves:
            sev = cve.severity
            if sev in breakdown:
                breakdown[sev] += 1
    return breakdown


def _do_scan(
    scan_path: str,
    severity: str | None,
    api_key: str | None,
) -> dict:
    """Internal scan logic shared by scan_repository."""
    resolved_key = _get_api_key(api_key)

    # Step 1: Detect dependencies
    detector = DependencyDetector()
    scan_result = detector.scan(scan_path)

    if not scan_result.dependencies:
        return {
            "status": "success",
            "message": "No dependencies found in the repository.",
            "scan": _serialize_scan_result(scan_result),
            "vulnerabilities": [],
            "summary": {"total_cves": 0, "severity_breakdown": {}},
        }

    # Step 2: Check for vulnerabilities
    client = NVDClient(api_key=resolved_key)
    matcher = VulnerabilityMatcher(client)
    vuln_results = matcher.check_dependencies(scan_result.dependencies)

    # Step 3: Filter by severity if specified
    if severity:
        min_level = SEVERITY_LEVELS.get(severity.upper(), 0)
        for result in vuln_results:
            result.cves = [
                cve for cve in result.cves
                if SEVERITY_LEVELS.get(cve.severity, 0) >= min_level
            ]

    # Serialize
    vulnerabilities = _serialize_vuln_results(vuln_results)
    breakdown = _severity_breakdown(vuln_results)
    total_cves = sum(breakdown.values())
    vulnerable_deps = sum(1 for r in vuln_results if r.is_vulnerable)

    return {
        "status": "success",
        "scan": _serialize_scan_result(scan_result),
        "vulnerabilities": vulnerabilities,
        "summary": {
            "total_cves": total_cves,
            "vulnerable_dependencies": vulnerable_deps,
            "total_dependencies": scan_result.total_dependencies,
            "severity_breakdown": breakdown,
        },
    }


def scan_repository(
    target: str,
    severity: str | None = None,
    api_key: str | None = None,
) -> str:
    """Scan a repository for vulnerable dependencies.

    Scans a Git repository URL or local directory path to detect
    third-party dependencies and check them against the NVD
    (National Vulnerability Database) for known CVEs.

    Args:
        target: Git repository URL (https://github.com/...) or local
                directory path to scan.
        severity: Minimum severity filter. Only return CVEs at this
                  level or above. Options: LOW, MEDIUM, HIGH, CRITICAL.
        api_key: Optional NVD API key for higher rate limits.
                 If not provided, uses NVD_API_KEY environment variable.

    Returns:
        JSON string with scan results including dependencies found,
        vulnerabilities detected, and severity breakdown.
    """
    try:
        if RepoManager.is_git_url(target):
            with RepoManager.temporary_clone(target) as repo_path:
                result = _do_scan(str(repo_path), severity, api_key)
                result["scanned_target"] = target
                return json.dumps(result, indent=2, ensure_ascii=False)
        else:
            path = Path(target)
            if not path.exists():
                return json.dumps({
                    "status": "error",
                    "message": f"Path does not exist: {target}",
                })
            result = _do_scan(str(path), severity, api_key)
            result["scanned_target"] = target
            return json.dumps(result, indent=2, ensure_ascii=False)

    except Exception as e:
        logger.exception(f"Error scanning {target}")
        return json.dumps({
            "status": "error",
            "message": str(e),
        })


def check_dependency(
    name: str,
    version: str,
    api_key: str | None = None,
) -> str:
    """Check a specific dependency for known vulnerabilities.

    Queries the NVD database to find CVEs associated with a specific
    package name and version.

    Args:
        name: The package/library name (e.g., "requests", "log4j").
        version: The version to check (e.g., "2.25.0", "2.14.1").
        api_key: Optional NVD API key for higher rate limits.

    Returns:
        JSON string with vulnerability information for the dependency.
    """
    try:
        resolved_key = _get_api_key(api_key)
        dep = Dependency(name=name, version=version, ecosystem="unknown")

        client = NVDClient(api_key=resolved_key)
        matcher = VulnerabilityMatcher(client)
        result = matcher.check_dependency(dep)

        vulnerabilities = _serialize_vuln_results([result])

        return json.dumps({
            "status": "success",
            "package": name,
            "version": version,
            "is_vulnerable": result.is_vulnerable,
            "total_cves": len(result.cves),
            "max_severity": result.max_severity,
            "max_score": result.max_score,
            "vulnerabilities": vulnerabilities,
        }, indent=2, ensure_ascii=False)

    except Exception as e:
        logger.exception(f"Error checking {name}@{version}")
        return json.dumps({
            "status": "error",
            "message": str(e),
        })


def list_supported_ecosystems() -> str:
    """List all supported dependency ecosystems and their file types.

    Returns information about which programming language ecosystems
    are supported and what dependency files are detected for each.

    Returns:
        JSON string with supported ecosystems and their file patterns.
    """
    ecosystems = {
        "python": {
            "files": [
                "requirements.txt",
                "Pipfile",
                "pyproject.toml",
                "setup.cfg",
            ],
            "description": "Python packages from PyPI",
        },
        "nodejs": {
            "files": ["package.json"],
            "description": "Node.js packages from npm",
        },
        "go": {
            "files": ["go.mod"],
            "description": "Go modules",
        },
        "java": {
            "files": ["pom.xml"],
            "description": "Java artifacts from Maven",
        },
        "ruby": {
            "files": ["Gemfile"],
            "description": "Ruby gems from RubyGems",
        },
    }

    return json.dumps({
        "status": "success",
        "ecosystems": ecosystems,
    }, indent=2, ensure_ascii=False)

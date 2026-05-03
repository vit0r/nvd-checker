"""
CLI interface for nvd-checker — provides scan, check, and report commands.
"""

from __future__ import annotations

import json
import os
import sys

import click
from rich.console import Console

from nvd_checker import __version__
from nvd_checker.nvd.client import NVDClient
from nvd_checker.nvd.matcher import VulnerabilityMatcher
from nvd_checker.report.generator import ReportGenerator
from nvd_checker.scanner.detector import DependencyDetector
from nvd_checker.utils import setup_logging

console = Console()

SEVERITY_LEVELS = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}


@click.group()
@click.version_option(version=__version__, prog_name="nvd-checker")
def cli() -> None:
    """🛡️  NVD Checker — Scan repositories for vulnerable dependencies.

    Detects third-party libraries in your project, queries the National
    Vulnerability Database (NVD) for known CVEs, and generates detailed
    reports with remediation tips.
    """


@cli.command()
@click.option(
    "--path", "-p",
    default=".",
    type=click.Path(exists=True, file_okay=False),
    help="Path to the repository to scan (default: current directory).",
)
@click.option(
    "--api-key", "-k",
    default=None,
    envvar="NVD_API_KEY",
    help="NVD API key (or set NVD_API_KEY env var). Increases rate limit.",
)
@click.option(
    "--severity", "-s",
    type=click.Choice(["LOW", "MEDIUM", "HIGH", "CRITICAL"], case_sensitive=False),
    default=None,
    help="Only show CVEs with this minimum severity.",
)
@click.option(
    "--format", "-f", "output_format",
    type=click.Choice(["terminal", "html", "json"], case_sensitive=False),
    default="terminal",
    help="Output format (default: terminal).",
)
@click.option(
    "--output", "-o",
    default=None,
    type=click.Path(),
    help="Output file path (required for html/json formats).",
)
@click.option(
    "--fail-on",
    type=click.Choice(["LOW", "MEDIUM", "HIGH", "CRITICAL"], case_sensitive=False),
    default=None,
    help="Exit with code 1 if any CVE meets or exceeds this severity (CI/CD).",
)
@click.option("--verbose", "-v", is_flag=True, help="Enable verbose output.")
def scan(
    path: str,
    api_key: str | None,
    severity: str | None,
    output_format: str,
    output: str | None,
    fail_on: str | None,
    verbose: bool,
) -> None:
    """Scan a repository for vulnerable dependencies."""
    logger = setup_logging(verbose)

    # Validate output path for non-terminal formats
    if output_format in ("html", "json") and not output:
        ext = "html" if output_format == "html" else "json"
        output = f"nvd-report.{ext}"
        logger.info(f"No output path specified, using: {output}")

    # Step 1: Scan dependencies
    console.print("\n[bold cyan]🔍 Scanning dependencies...[/]\n")
    detector = DependencyDetector()
    scan_result = detector.scan(path)

    if not scan_result.dependencies:
        console.print("[yellow]⚠ No dependencies found in the repository.[/]")
        console.print("[dim]Make sure the repository contains dependency files like "
                      "requirements.txt, package.json, go.mod, etc.[/]")
        return

    console.print(
        f"[green]Found {scan_result.total_dependencies} dependencies "
        f"in {len(scan_result.files_scanned)} file(s)[/]\n"
    )

    # Step 2: Check for vulnerabilities
    console.print("[bold cyan]🌐 Querying NVD for vulnerabilities...[/]\n")
    if not api_key:
        console.print(
            "[dim]💡 Tip: Set NVD_API_KEY for faster queries "
            "(https://nvd.nist.gov/developers/request-an-api-key)[/]\n"
        )

    client = NVDClient(api_key=api_key)
    matcher = VulnerabilityMatcher(client)
    vuln_results = matcher.check_dependencies(scan_result.dependencies)

    # Filter by severity if specified
    if severity:
        min_level = SEVERITY_LEVELS.get(severity.upper(), 0)
        for result in vuln_results:
            result.cves = [
                cve for cve in result.cves
                if SEVERITY_LEVELS.get(cve.severity, 0) >= min_level
            ]

    # Step 3: Generate report
    console.print("\n[bold cyan]📊 Generating report...[/]\n")
    report = ReportGenerator(scan_result, vuln_results)

    if output_format == "terminal":
        report.to_terminal()
    elif output_format == "html":
        report.to_html(output)
        console.print(f"[green]✅ HTML report saved to: {output}[/]")
    elif output_format == "json":
        report.to_json(output)
        console.print(f"[green]✅ JSON report saved to: {output}[/]")

    # CI/CD exit code
    if fail_on:
        fail_level = SEVERITY_LEVELS.get(fail_on.upper(), 0)
        for result in vuln_results:
            for cve in result.cves:
                if SEVERITY_LEVELS.get(cve.severity, 0) >= fail_level:
                    console.print(
                        f"\n[bold red]❌ FAIL: Found {cve.severity} vulnerability "
                        f"({cve.cve_id}) — threshold: {fail_on.upper()}[/]"
                    )
                    sys.exit(1)


@cli.command()
@click.option("--name", "-n", required=True, help="Dependency name.")
@click.option("--version", "-V", "dep_version", required=True, help="Dependency version.")
@click.option(
    "--api-key", "-k",
    default=None,
    envvar="NVD_API_KEY",
    help="NVD API key.",
)
@click.option("--verbose", "-v", is_flag=True, help="Enable verbose output.")
def check(
    name: str,
    dep_version: str,
    api_key: str | None,
    verbose: bool,
) -> None:
    """Check a specific dependency for known vulnerabilities."""
    logger = setup_logging(verbose)

    from nvd_checker.scanner.base import Dependency, ScanResult

    console.print(
        f"\n[bold cyan]🔍 Checking {name}@{dep_version} for vulnerabilities...[/]\n"
    )

    dep = Dependency(name=name, version=dep_version, ecosystem="unknown")
    client = NVDClient(api_key=api_key)
    matcher = VulnerabilityMatcher(client)
    result = matcher.check_dependency(dep)

    scan_result = ScanResult(
        repo_path="(single check)",
        dependencies=[dep],
    )

    report = ReportGenerator(scan_result, [result])
    report.to_terminal()


@cli.command()
@click.argument("input_file", type=click.Path(exists=True))
@click.option(
    "--format", "-f", "output_format",
    type=click.Choice(["html", "terminal"], case_sensitive=False),
    default="html",
    help="Output format (default: html).",
)
@click.option(
    "--output", "-o",
    default=None,
    type=click.Path(),
    help="Output file path.",
)
def report(input_file: str, output_format: str, output: str | None) -> None:
    """Generate a report from a previous scan JSON file."""
    setup_logging(False)

    from nvd_checker.nvd.models import CVERecord, CVSSScore, Weakness, Reference
    from nvd_checker.nvd.matcher import VulnerabilityResult
    from nvd_checker.scanner.base import Dependency, ScanResult

    with open(input_file, "r", encoding="utf-8") as f:
        data = json.load(f)

    # Reconstruct objects from JSON
    scan_result = ScanResult(
        repo_path=data.get("scan", {}).get("repo_path", ""),
        files_scanned=data.get("scan", {}).get("files_scanned", []),
    )

    vuln_map: dict[str, VulnerabilityResult] = {}
    for v in data.get("vulnerabilities", []):
        key = f"{v['package']}:{v['version']}"
        if key not in vuln_map:
            dep = Dependency(
                name=v["package"],
                version=v.get("version"),
                ecosystem=v.get("ecosystem", "unknown"),
            )
            vuln_map[key] = VulnerabilityResult(dependency=dep)
            scan_result.dependencies.append(dep)

        cve = CVERecord(
            cve_id=v["cve_id"],
            description=v.get("description", ""),
            published=v.get("published", ""),
            cvss=CVSSScore(
                base_score=v.get("score", 0.0),
                base_severity=v.get("severity", "UNKNOWN"),
            ),
        )
        if v.get("cwe") and v["cwe"] != "N/A":
            cve.weaknesses.append(Weakness(cwe_id=v["cwe"]))

        vuln_map[key].cves.append(cve)

    vuln_results = list(vuln_map.values())
    gen = ReportGenerator(scan_result, vuln_results)

    if output_format == "terminal":
        gen.to_terminal()
    elif output_format == "html":
        if not output:
            output = "nvd-report.html"
        gen.to_html(output)
        console.print(f"[green]✅ HTML report saved to: {output}[/]")

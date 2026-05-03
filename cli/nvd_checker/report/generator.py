"""
Report generator — produces vulnerability reports in terminal (Rich),
HTML (Jinja2), and JSON formats.
"""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from pathlib import Path

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from nvd_checker.nvd.matcher import VulnerabilityResult
from nvd_checker.report.advisor import SecurityAdvisor
from nvd_checker.scanner.base import ScanResult

logger = logging.getLogger("nvd_checker")

SEVERITY_COLORS = {
    "CRITICAL": "bold red",
    "HIGH": "bold bright_red",
    "MEDIUM": "bold yellow",
    "LOW": "bold green",
    "NONE": "dim",
    "UNKNOWN": "dim",
}

SEVERITY_ORDER = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "NONE": 0, "UNKNOWN": -1}


class ReportGenerator:
    """Generates vulnerability reports in multiple formats."""

    def __init__(
        self,
        scan_result: ScanResult,
        vuln_results: list[VulnerabilityResult],
    ) -> None:
        self.scan_result = scan_result
        self.vuln_results = vuln_results
        self.advisor = SecurityAdvisor()
        self._timestamp = datetime.now(timezone.utc).isoformat()

    @property
    def vulnerable_results(self) -> list[VulnerabilityResult]:
        return [r for r in self.vuln_results if r.is_vulnerable]

    @property
    def total_cves(self) -> int:
        return sum(len(r.cves) for r in self.vuln_results)

    @property
    def severity_breakdown(self) -> dict[str, int]:
        breakdown: dict[str, int] = {
            "CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0,
        }
        for result in self.vuln_results:
            for cve in result.cves:
                sev = cve.severity
                if sev in breakdown:
                    breakdown[sev] += 1
        return breakdown

    # ─── Terminal Report (Rich) ────────────────────────────────

    def to_terminal(self) -> None:
        """Print a formatted vulnerability report to the terminal."""
        console = Console()
        console.print()

        # Header
        console.print(
            Panel.fit(
                "[bold cyan]🛡️  NVD Vulnerability Report[/]",
                border_style="cyan",
            )
        )
        console.print()

        # Summary
        self._print_summary(console)
        console.print()

        if not self.vulnerable_results:
            console.print(
                "[bold green]✅ No known vulnerabilities found![/]"
            )
            console.print()
            return

        # Vulnerability table
        self._print_vuln_table(console)
        console.print()

        # Detailed CVE info with remediation
        self._print_cve_details(console)

    def _print_summary(self, console: Console) -> None:
        """Print scan summary panel."""
        breakdown = self.severity_breakdown
        summary_lines = [
            f"[bold]Repository:[/] {self.scan_result.repo_path}",
            f"[bold]Files scanned:[/] {len(self.scan_result.files_scanned)}",
            f"[bold]Dependencies found:[/] {self.scan_result.total_dependencies}",
            f"[bold]Vulnerable deps:[/] {len(self.vulnerable_results)}",
            f"[bold]Total CVEs:[/] {self.total_cves}",
            "",
            "[bold]Severity breakdown:[/]",
            f"  🔴 Critical: {breakdown['CRITICAL']}",
            f"  🟠 High: {breakdown['HIGH']}",
            f"  🟡 Medium: {breakdown['MEDIUM']}",
            f"  🟢 Low: {breakdown['LOW']}",
        ]
        console.print(
            Panel(
                "\n".join(summary_lines),
                title="[bold]Scan Summary[/]",
                border_style="blue",
            )
        )

    def _print_vuln_table(self, console: Console) -> None:
        """Print a table of vulnerable dependencies."""
        table = Table(
            title="Vulnerable Dependencies",
            show_header=True,
            header_style="bold magenta",
        )
        table.add_column("Package", style="cyan", no_wrap=True)
        table.add_column("Version", style="white")
        table.add_column("Ecosystem", style="dim")
        table.add_column("CVEs", justify="right")
        table.add_column("Max Severity", justify="center")
        table.add_column("Max Score", justify="right")

        # Sort by max severity descending
        sorted_results = sorted(
            self.vulnerable_results,
            key=lambda r: SEVERITY_ORDER.get(r.max_severity, 0),
            reverse=True,
        )

        for result in sorted_results:
            severity_style = SEVERITY_COLORS.get(
                result.max_severity, "dim"
            )
            table.add_row(
                result.dependency.name,
                result.dependency.version or "?",
                result.dependency.ecosystem,
                str(len(result.cves)),
                Text(result.max_severity, style=severity_style),
                f"{result.max_score:.1f}",
            )

        console.print(table)

    def _print_cve_details(self, console: Console) -> None:
        """Print detailed CVE information with remediation tips."""
        console.print("[bold]── CVE Details & Remediation ──[/]")
        console.print()

        for result in self.vulnerable_results:
            for cve in sorted(
                result.cves,
                key=lambda c: SEVERITY_ORDER.get(c.severity, 0),
                reverse=True,
            ):
                advice = self.advisor.get_advice(
                    cve, result.dependency.name
                )
                severity_style = SEVERITY_COLORS.get(cve.severity, "dim")

                lines = [
                    f"[bold]Package:[/] {result.dependency.display_name}",
                    f"[bold]Score:[/] [{severity_style}]{cve.score} ({cve.severity})[/]",
                    f"[bold]CVSS:[/] {cve.cvss.vector_string or 'N/A'}",
                    f"[bold]CWE:[/] {cve.primary_cwe}",
                    f"[bold]Published:[/] {cve.published[:10] if cve.published else 'N/A'}",
                    "",
                    f"[bold]Description:[/] {cve.description[:300]}",
                    "",
                    f"[bold]Urgency:[/] {advice['urgency']}",
                    f"[bold]Recommendation:[/] {advice['update_recommendation']}",
                ]

                cwe_guidance = advice.get("cwe_guidance")
                if cwe_guidance:
                    lines.append(f"[bold]CWE Guidance:[/] {cwe_guidance}")

                if advice["fix_steps"]:
                    lines.append("")
                    lines.append("[bold]Fix steps:[/]")
                    for i, step in enumerate(advice["fix_steps"], 1):
                        lines.append(f"  {i}. {step}")

                if advice["references"]:
                    lines.append("")
                    lines.append("[bold]References:[/]")
                    for url in advice["references"][:3]:
                        lines.append(f"  → {url}")

                console.print(
                    Panel(
                        "\n".join(lines),
                        title=f"[{severity_style}]{cve.cve_id}[/]",
                        border_style=severity_style.replace("bold ", ""),
                        expand=True,
                    )
                )
                console.print()

    # ─── JSON Report ───────────────────────────────────────────

    def to_json(self, output_path: str) -> None:
        """Export the report as a structured JSON file."""
        data = {
            "report_timestamp": self._timestamp,
            "scan": {
                "repo_path": self.scan_result.repo_path,
                "files_scanned": self.scan_result.files_scanned,
                "total_dependencies": self.scan_result.total_dependencies,
            },
            "summary": {
                "total_cves": self.total_cves,
                "vulnerable_dependencies": len(self.vulnerable_results),
                "severity_breakdown": self.severity_breakdown,
            },
            "vulnerabilities": [],
        }

        for result in self.vuln_results:
            if not result.is_vulnerable:
                continue
            for cve in result.cves:
                advice = self.advisor.get_advice(cve, result.dependency.name)
                data["vulnerabilities"].append({
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
                    "advice": advice,
                })

        Path(output_path).write_text(
            json.dumps(data, indent=2, ensure_ascii=False),
            encoding="utf-8",
        )
        logger.info(f"JSON report saved to {output_path}")

    # ─── HTML Report ───────────────────────────────────────────

    def to_html(self, output_path: str) -> None:
        """Generate a standalone HTML vulnerability report."""
        try:
            from jinja2 import Template
        except ImportError:
            logger.error("Jinja2 is required for HTML reports: pip install jinja2")
            return

        template_path = Path(__file__).parent / "templates" / "report.html"
        if not template_path.exists():
            logger.error(f"HTML template not found: {template_path}")
            return

        template = Template(
            template_path.read_text(encoding="utf-8")
        )

        # Prepare template data
        vulnerabilities = []
        for result in self.vulnerable_results:
            for cve in sorted(
                result.cves,
                key=lambda c: SEVERITY_ORDER.get(c.severity, 0),
                reverse=True,
            ):
                advice = self.advisor.get_advice(cve, result.dependency.name)
                vulnerabilities.append({
                    "package": result.dependency.name,
                    "version": result.dependency.version or "?",
                    "ecosystem": result.dependency.ecosystem,
                    "cve": cve,
                    "advice": advice,
                })

        html = template.render(
            timestamp=self._timestamp,
            scan=self.scan_result,
            total_cves=self.total_cves,
            vulnerable_count=len(self.vulnerable_results),
            severity_breakdown=self.severity_breakdown,
            vulnerabilities=vulnerabilities,
        )

        Path(output_path).write_text(html, encoding="utf-8")
        logger.info(f"HTML report saved to {output_path}")

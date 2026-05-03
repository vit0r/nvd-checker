"""
Report generation module — terminal, HTML, and JSON output
for vulnerability scan results.
"""

from nvd_checker.report.generator import ReportGenerator
from nvd_checker.report.advisor import SecurityAdvisor

__all__ = ["ReportGenerator", "SecurityAdvisor"]

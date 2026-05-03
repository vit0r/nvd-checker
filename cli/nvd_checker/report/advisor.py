"""
Security advisor — generates remediation tips and fix recommendations
for each CVE based on CWE type, CVSS score, and available references.
"""

from __future__ import annotations

from nvd_checker.nvd.models import CVERecord


# Common CWE remediation guidance
CWE_REMEDIATION: dict[str, dict[str, str]] = {
    "CWE-79": {
        "name": "Cross-site Scripting (XSS)",
        "tip": "Sanitize all user inputs. Use context-aware output encoding. "
               "Implement Content Security Policy (CSP) headers.",
    },
    "CWE-89": {
        "name": "SQL Injection",
        "tip": "Use parameterized queries or prepared statements. "
               "Never concatenate user input into SQL strings. "
               "Use an ORM when possible.",
    },
    "CWE-78": {
        "name": "OS Command Injection",
        "tip": "Avoid passing user input to system commands. "
               "Use allowlists for permitted commands. "
               "Use language-specific APIs instead of shell commands.",
    },
    "CWE-20": {
        "name": "Improper Input Validation",
        "tip": "Validate all inputs on the server side. Use allowlists "
               "over denylists. Implement strict type checking.",
    },
    "CWE-22": {
        "name": "Path Traversal",
        "tip": "Canonicalize file paths before use. Use chroot or "
               "sandbox environments. Validate that resolved paths "
               "stay within expected directories.",
    },
    "CWE-119": {
        "name": "Buffer Overflow",
        "tip": "Use memory-safe languages or safe string functions. "
               "Enable ASLR, DEP, and stack canaries. Perform bounds "
               "checking on all buffer operations.",
    },
    "CWE-200": {
        "name": "Information Exposure",
        "tip": "Remove sensitive data from error messages and logs. "
               "Implement proper access controls. Use encryption "
               "for sensitive data at rest and in transit.",
    },
    "CWE-287": {
        "name": "Improper Authentication",
        "tip": "Use established authentication frameworks. Implement "
               "multi-factor authentication. Never store passwords "
               "in plaintext.",
    },
    "CWE-306": {
        "name": "Missing Authentication",
        "tip": "Require authentication for all sensitive operations. "
               "Implement proper session management. Use the principle "
               "of least privilege.",
    },
    "CWE-352": {
        "name": "Cross-Site Request Forgery (CSRF)",
        "tip": "Use anti-CSRF tokens. Verify the Origin and Referer "
               "headers. Use SameSite cookie attribute.",
    },
    "CWE-400": {
        "name": "Uncontrolled Resource Consumption",
        "tip": "Implement rate limiting and request throttling. "
               "Set timeouts and resource limits. Monitor resource usage.",
    },
    "CWE-502": {
        "name": "Deserialization of Untrusted Data",
        "tip": "Never deserialize data from untrusted sources. "
               "Use safe serialization formats (JSON over pickle/YAML). "
               "Implement integrity checks.",
    },
    "CWE-611": {
        "name": "XML External Entity (XXE)",
        "tip": "Disable DTD processing and external entities in XML "
               "parsers. Use less complex data formats like JSON.",
    },
    "CWE-776": {
        "name": "XML Entity Expansion (Billion Laughs)",
        "tip": "Limit entity expansion depth. Disable DTD processing. "
               "Use streaming parsers with size limits.",
    },
    "CWE-918": {
        "name": "Server-Side Request Forgery (SSRF)",
        "tip": "Validate and sanitize all URLs. Use allowlists for "
               "permitted domains. Block requests to internal networks.",
    },
}


class SecurityAdvisor:
    """Generates remediation tips and fix guidance for CVE records."""

    def get_advice(self, cve: CVERecord, dep_name: str = "") -> dict:
        """Generate comprehensive remediation advice for a CVE.

        Returns dict with keys: urgency, fix_steps, cwe_guidance,
        references, update_recommendation.
        """
        advice: dict = {
            "urgency": self._get_urgency(cve),
            "fix_steps": self._get_fix_steps(cve, dep_name),
            "cwe_guidance": self._get_cwe_guidance(cve),
            "references": self._get_useful_references(cve),
            "update_recommendation": self._get_update_recommendation(
                cve, dep_name
            ),
        }
        return advice

    @staticmethod
    def _get_urgency(cve: CVERecord) -> str:
        """Classify urgency based on CVSS score."""
        score = cve.score
        if score >= 9.0:
            return "🚨 CRITICAL — Fix immediately! This vulnerability is actively dangerous."
        elif score >= 7.0:
            return "🔶 HIGH — Fix as soon as possible. Schedule for the current sprint."
        elif score >= 4.0:
            return "🟡 MEDIUM — Plan a fix within the next release cycle."
        elif score > 0:
            return "🟢 LOW — Low risk. Fix when convenient."
        return "ℹ️  Severity not scored. Review manually."

    @staticmethod
    def _get_fix_steps(cve: CVERecord, dep_name: str) -> list[str]:
        """Generate ordered fix steps."""
        steps = []

        if dep_name:
            steps.append(
                f"Check if a patched version of '{dep_name}' is available."
            )
            steps.append(
                f"Update '{dep_name}' to the latest stable version "
                f"that fixes {cve.cve_id}."
            )

        steps.append(
            f"Review the full CVE details at {cve.nvd_url}"
        )
        steps.append(
            "Test your application after updating to ensure "
            "compatibility."
        )

        if cve.score >= 7.0:
            steps.append(
                "Consider performing a security audit of related "
                "components."
            )

        return steps

    def _get_cwe_guidance(self, cve: CVERecord) -> str | None:
        """Get CWE-specific remediation guidance."""
        for weakness in cve.weaknesses:
            cwe_id = weakness.cwe_id
            if cwe_id in CWE_REMEDIATION:
                info = CWE_REMEDIATION[cwe_id]
                return f"[{cwe_id}] {info['name']}: {info['tip']}"
        return None

    @staticmethod
    def _get_useful_references(cve: CVERecord) -> list[str]:
        """Extract the most useful reference URLs."""
        useful = []
        for ref in cve.references:
            tags = ref.tags
            if any(
                t in tags
                for t in ("Patch", "Vendor Advisory", "Release Notes")
            ):
                useful.append(ref.url)
            elif len(useful) < 3:
                useful.append(ref.url)
        return useful[:5]

    @staticmethod
    def _get_update_recommendation(
        cve: CVERecord, dep_name: str
    ) -> str:
        """Generate update recommendation text."""
        if not dep_name:
            return "Update the affected component to a non-vulnerable version."

        # Check CPE matches for fixed versions
        for match in cve.cpe_matches:
            if match.version_end:
                return (
                    f"Update '{dep_name}' to a version newer than "
                    f"{match.version_end}."
                )

        return (
            f"Update '{dep_name}' to the latest stable version. "
            f"Check the project's changelog for security fixes."
        )

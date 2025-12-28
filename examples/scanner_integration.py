#!/usr/bin/env python3

"""
Project: BRS-KB (BRS XSS Knowledge Base)
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: 2025-10-14 22:53:00 MSK
Status: Created
Telegram: https://t.me/easyprotech

Example: Integrating BRS-KB into a Security Scanner
"""

from typing import Any, Dict, List

from brs_kb import get_vulnerability_details


class VulnerabilityScanner:
    """Example scanner that uses BRS-KB for vulnerability reporting."""

    def __init__(self):
        self.findings: List[Dict[str, Any]] = []

    def scan_url(self, url: str, test_payload: str) -> Dict[str, Any]:
        """
        Simulate scanning a URL for XSS vulnerabilities.

        In a real scanner, this would:
        1. Inject test payload
        2. Analyze response
        3. Detect vulnerability context
        4. Enrich with KB data
        """
        # Simulated detection
        detected_context = self._detect_context(test_payload)

        if detected_context:
            # Enrich with knowledge base data
            kb_details = get_vulnerability_details(detected_context)

            finding = {
                "url": url,
                "payload": test_payload,
                "context": detected_context,
                "severity": kb_details.get("severity", "unknown"),
                "cvss_score": kb_details.get("cvss_score", 0.0),
                "title": kb_details.get("title", "Unknown XSS"),
                "description": kb_details.get("description", ""),
                "remediation": kb_details.get("remediation", ""),
                "cwe": kb_details.get("cwe", []),
                "owasp": kb_details.get("owasp", []),
            }

            self.findings.append(finding)
            return finding

        return {}

    def _detect_context(self, payload: str) -> str:
        """Simulate context detection based on payload."""
        if "<script>" in payload:
            return "html_content"
        elif "javascript:" in payload:
            return "url"
        elif "onerror=" in payload:
            return "html_attribute"
        elif "{{" in payload:
            return "template_injection"
        return "default"

    def generate_report(self) -> str:
        """Generate a formatted vulnerability report."""
        if not self.findings:
            return "No vulnerabilities found."

        report = []
        report.append("=" * 80)
        report.append("VULNERABILITY SCAN REPORT")
        report.append("=" * 80)
        report.append(f"Total findings: {len(self.findings)}")
        report.append("")

        for i, finding in enumerate(self.findings, 1):
            report.append(f"[{i}] {finding['title']}")
            report.append("-" * 80)
            report.append(f"URL: {finding['url']}")
            report.append(f"Context: {finding['context']}")
            report.append(f"Severity: {finding['severity'].upper()}")
            report.append(f"CVSS Score: {finding['cvss_score']}")
            report.append(f"CWE: {', '.join(finding['cwe'])}")
            report.append(f"OWASP: {', '.join(finding['owasp'])}")
            report.append(f"Payload: {finding['payload']}")
            report.append("")
            report.append("Description:")
            report.append(finding["description"][:300] + "...")
            report.append("")
            report.append("Remediation:")
            report.append(finding["remediation"][:300] + "...")
            report.append("")
            report.append("=" * 80)
            report.append("")

        return "\n".join(report)


def main():
    """Demonstrate scanner integration."""

    print("BRS-KB Scanner Integration Example")
    print("=" * 80)
    print()

    # Create scanner instance
    scanner = VulnerabilityScanner()

    # Simulate scanning multiple URLs
    test_cases = [
        ("https://example.com/search?q=test", "<script>alert(1)</script>"),
        ("https://example.com/profile?name=user", "<img src=x onerror=alert(1)>"),
        ("https://example.com/redirect?url=target", "javascript:alert(1)"),
        ("https://example.com/api/user", "{{constructor.constructor('alert(1)')()}}"),
    ]

    print("Scanning URLs for XSS vulnerabilities...")
    print()

    for url, payload in test_cases:
        print(f"Testing: {url}")
        finding = scanner.scan_url(url, payload)
        if finding:
            print(f"  Found: {finding['context']} (Severity: {finding['severity']})")
        print()

    # Generate and print report
    print("\n")
    report = scanner.generate_report()
    print(report)

    print("\nIntegration demonstration complete!")
    print("BRS-KB automatically enriched findings with comprehensive vulnerability data.")


if __name__ == "__main__":
    main()

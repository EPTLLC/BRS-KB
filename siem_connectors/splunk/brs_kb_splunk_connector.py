#!/usr/bin/env python3

"""
BRS-KB Splunk Integration Connector
Project: BRS-KB (BRS XSS Knowledge Base)
Company: EasyProTech LLC (www.easyprotech)
Dev: Brabus
Date: Sat 25 Oct 2025 12:00:00 UTC
Status: Created
Telegram: https://t.me/easyprotech

Splunk HTTP Event Collector integration for BRS-KB XSS vulnerability data
"""

import time
from typing import Any, Dict, List, Optional

import requests


# Version from single source
try:
    from brs_kb.version import __version__ as BRS_KB_VERSION
except ImportError:
    BRS_KB_VERSION = "4.0.0"  # Fallback for standalone use


class BRSKBSplunkConnector:
    """BRS-KB Splunk integration for real-time security event ingestion"""

    def __init__(self, splunk_url: str, api_key: str, index: str = "brs_kb_security"):
        """
        Initialize Splunk connector

        Args:
            splunk_url: Splunk HTTP Event Collector URL (e.g., https://splunk:8088/services/collector)
            api_key: Splunk HEC token
            index: Target index name
        """
        self.splunk_url = splunk_url.rstrip("/")
        self.api_key = api_key
        self.index = index

        self.session = requests.Session()
        self.session.headers.update(
            {"Authorization": f"Splunk {api_key}", "Content-Type": "application/json"}
        )

    def send_vulnerability_event(self, vulnerability_data: Dict[str, Any]) -> bool:
        """
        Send XSS vulnerability event to Splunk

        Args:
            vulnerability_data: Vulnerability information from BRS-KB

        Returns:
            bool: Success status
        """
        try:
            # Format event for Splunk
            event = self._format_vulnerability_event(vulnerability_data)

            # Send to Splunk
            response = self.session.post(f"{self.splunk_url}/event", json=event, timeout=30)

            if response.status_code == 200:
                print(
                    f" Vulnerability event sent to Splunk: {vulnerability_data.get('context', 'unknown')}"
                )
                return True
            else:
                print(f" Failed to send event to Splunk: {response.status_code} - {response.text}")
                return False

        except Exception as e:
            print(f" Error sending vulnerability to Splunk: {e}")
            return False

    def send_payload_analysis(self, analysis_data: Dict[str, Any]) -> bool:
        """
        Send payload analysis results to Splunk

        Args:
            analysis_data: Payload analysis from BRS-KB

        Returns:
            bool: Success status
        """
        try:
            event = self._format_payload_analysis_event(analysis_data)

            response = self.session.post(f"{self.splunk_url}/event", json=event, timeout=30)

            if response.status_code == 200:
                print(
                    f" Payload analysis sent to Splunk: {analysis_data.get('payload', 'unknown')[:50]}..."
                )
                return True
            else:
                print(f" Failed to send payload analysis to Splunk: {response.status_code}")
                return False

        except Exception as e:
            print(f" Error sending payload analysis to Splunk: {e}")
            return False

    def send_security_alert(self, alert_data: Dict[str, Any]) -> bool:
        """
        Send security alert to Splunk

        Args:
            alert_data: Alert information

        Returns:
            bool: Success status
        """
        try:
            event = self._format_security_alert_event(alert_data)

            response = self.session.post(f"{self.splunk_url}/event", json=event, timeout=30)

            if response.status_code == 200:
                print(
                    f"🚨 Security alert sent to Splunk: {alert_data.get('alert_type', 'unknown')}"
                )
                return True
            else:
                print(f" Failed to send security alert to Splunk: {response.status_code}")
                return False

        except Exception as e:
            print(f" Error sending security alert to Splunk: {e}")
            return False

    def _format_vulnerability_event(self, vulnerability_data: Dict[str, Any]) -> Dict[str, Any]:
        """Format vulnerability data for Splunk ingestion"""
        return {
            "time": int(time.time()),
            "source": "brs_kb_vulnerability",
            "sourcetype": "brs_kb:xss_vulnerability",
            "index": self.index,
            "event": {
                "event_type": "xss_vulnerability_detected",
                "context": vulnerability_data.get("context", "unknown"),
                "severity": vulnerability_data.get("severity", "unknown"),
                "cvss_score": vulnerability_data.get("cvss_score", 0.0),
                "confidence": vulnerability_data.get("confidence", 0.0),
                "payload": vulnerability_data.get("payload", ""),
                "description": vulnerability_data.get("description", ""),
                "remediation": vulnerability_data.get("remediation", ""),
                "cwe": vulnerability_data.get("cwe", []),
                "owasp": vulnerability_data.get("owasp", []),
                "tags": vulnerability_data.get("tags", []),
                "metadata": {
                    "source_system": "brs_kb",
                    "version": BRS_KB_VERSION,
                    "analysis_method": vulnerability_data.get("analysis_method", "unknown"),
                    "browser_support": vulnerability_data.get("browser_support", []),
                    "waf_evasion": vulnerability_data.get("waf_evasion", False),
                },
            },
        }

    def _format_payload_analysis_event(self, analysis_data: Dict[str, Any]) -> Dict[str, Any]:
        """Format payload analysis data for Splunk ingestion"""
        return {
            "time": int(time.time()),
            "source": "brs_kb_payload_analysis",
            "sourcetype": "brs_kb:payload_analysis",
            "index": self.index,
            "event": {
                "event_type": "payload_analysis",
                "payload": analysis_data.get("payload", ""),
                "contexts": analysis_data.get("contexts", []),
                "severity": analysis_data.get("severity", "unknown"),
                "confidence": analysis_data.get("confidence", 0.0),
                "analysis_method": analysis_data.get("analysis_method", "unknown"),
                "effectiveness_score": analysis_data.get("effectiveness_score", 0.0),
                "risk_level": analysis_data.get("risk_level", "unknown"),
                "recommendations": analysis_data.get("recommendations", []),
                "metadata": {
                    "source_system": "brs_kb",
                    "version": BRS_KB_VERSION,
                    "waf_detected": analysis_data.get("waf_detected", []),
                    "browser_parsing": analysis_data.get("browser_parsing", {}),
                },
            },
        }

    def _format_security_alert_event(self, alert_data: Dict[str, Any]) -> Dict[str, Any]:
        """Format security alert for Splunk ingestion"""
        return {
            "time": int(time.time()),
            "source": "brs_kb_security_alert",
            "sourcetype": "brs_kb:security_alert",
            "index": self.index,
            "event": {
                "event_type": "security_alert",
                "alert_type": alert_data.get("alert_type", "unknown"),
                "severity": alert_data.get("severity", "medium"),
                "title": alert_data.get("title", ""),
                "description": alert_data.get("description", ""),
                "context": alert_data.get("context", ""),
                "cvss_score": alert_data.get("cvss_score", 0.0),
                "affected_systems": alert_data.get("affected_systems", []),
                "immediate_actions": alert_data.get("immediate_actions", []),
                "metadata": {
                    "source_system": "brs_kb",
                    "version": BRS_KB_VERSION,
                    "alert_id": alert_data.get("alert_id", ""),
                    "escalation_required": alert_data.get("escalation_required", False),
                },
            },
        }

    def test_connection(self) -> bool:
        """Test connection to Splunk"""
        try:
            response = self.session.get(f"{self.splunk_url}/health", timeout=10)
            return response.status_code == 200
        except Exception:
            return False

    def create_search_query(
        self,
        context: Optional[str] = None,
        severity: Optional[str] = None,
        time_range: str = "-24h",
    ) -> str:
        """
        Create Splunk search query for BRS-KB data

        Args:
            context: XSS context filter (optional)
            severity: Severity filter (optional)
            time_range: Time range (optional)

        Returns:
            str: Splunk search query
        """
        query_parts = ["index=brs_kb_security"]

        if context:
            query_parts.append(f'context="{context}"')

        if severity:
            query_parts.append(f'severity="{severity}"')

        query_parts.append(f"earliest={time_range}")

        return " | ".join(query_parts)

    def get_dashboard_queries(self) -> Dict[str, str]:
        """Get predefined dashboard queries for BRS-KB data"""
        return {
            "xss_context_distribution": """
                index=brs_kb_security sourcetype=brs_kb:xss_vulnerability
                | stats count by context
                | sort -count
            """,
            "severity_trends": """
                index=brs_kb_security sourcetype=brs_kb:xss_vulnerability
                | timechart count by severity
            """,
            "top_payloads": """
                index=brs_kb_security sourcetype=brs_kb:xss_vulnerability
                | stats count by payload
                | sort -count
                | head 10
            """,
            "waf_bypass_detection": """
                index=brs_kb_security sourcetype=brs_kb:xss_vulnerability waf_evasion=true
                | stats count by context
            """,
            "critical_alerts": """
                index=brs_kb_security sourcetype=brs_kb:security_alert severity=critical
                | table _time, title, description, context, cvss_score
            """,
        }


def create_sample_vulnerability_data() -> List[Dict[str, Any]]:
    """Create sample vulnerability data for testing"""
    return [
        {
            "context": "websocket_xss",
            "severity": "high",
            "cvss_score": 7.5,
            "confidence": 0.95,
            "payload": '{"type": "chat", "message": "<script>alert(1)</script>"}',
            "description": "WebSocket XSS vulnerability detected",
            "remediation": "Implement message sanitization and CSP",
            "cwe": ["CWE-79"],
            "owasp": ["A03:2021"],
            "tags": ["websocket", "realtime", "json"],
            "analysis_method": "pattern_matching",
            "browser_support": ["chrome", "firefox", "safari", "edge"],
            "waf_evasion": False,
        },
        {
            "context": "html_content",
            "severity": "critical",
            "cvss_score": 8.8,
            "confidence": 1.0,
            "payload": "<script>alert('XSS')</script>",
            "description": "Classic script tag injection",
            "remediation": "Use HTML entity encoding",
            "cwe": ["CWE-79"],
            "owasp": ["A03:2021"],
            "tags": ["script", "classic", "basic"],
            "analysis_method": "payload_database",
            "browser_support": ["chrome", "firefox", "safari", "edge"],
            "waf_evasion": False,
        },
        {
            "context": "template_injection",
            "severity": "critical",
            "cvss_score": 9.0,
            "confidence": 0.98,
            "payload": "{{constructor.constructor('alert(1)')()}}",
            "description": "Template injection with sandbox escape",
            "remediation": "Use template sandboxing and AOT compilation",
            "cwe": ["CWE-94"],
            "owasp": ["A03:2021"],
            "tags": ["template", "sandbox-escape", "code-execution"],
            "analysis_method": "pattern_matching",
            "browser_support": ["chrome", "firefox", "safari", "edge"],
            "waf_evasion": True,
        },
    ]


def main():
    """Main function for testing and demonstration"""
    print("BRS-KB Splunk Integration Connector")
    print("=" * 50)
    print()

    # Configuration
    splunk_url = "https://your-splunk.com:8088/services/collector"
    api_key = "your-splunk-hec-token"
    index = "brs_kb_security"

    # Initialize connector
    connector = BRSKBSplunkConnector(splunk_url, api_key, index)

    print(" Connector initialized")
    print(f" Splunk URL: {splunk_url}")
    print(f" Target Index: {index}")
    print()

    # Test connection
    if connector.test_connection():
        print(" Splunk connection successful")
    else:
        print(" Splunk connection failed")
        print("Please verify your Splunk configuration")
        return 1

    print()

    # Send sample vulnerability data
    print("📤 Sending sample vulnerability events...")

    sample_data = create_sample_vulnerability_data()
    sent_count = 0

    for vuln_data in sample_data:
        if connector.send_vulnerability_event(vuln_data):
            sent_count += 1

    print(f" Sent {sent_count}/{len(sample_data)} vulnerability events")
    print()

    # Create sample payload analysis
    sample_analysis = {
        "payload": "<script>alert('XSS')</script>",
        "contexts": ["html_content", "html_comment"],
        "severity": "critical",
        "confidence": 1.0,
        "analysis_method": "payload_database",
        "effectiveness_score": 0.95,
        "risk_level": "critical",
        "recommendations": [
            "Implement strict input validation",
            "Use HTML entity encoding",
            "Deploy Content Security Policy (CSP)",
        ],
        "waf_detected": [],
        "browser_parsing": {
            "script_execution": True,
            "html_injection": True,
            "event_execution": False,
            "css_injection": False,
        },
    }

    if connector.send_payload_analysis(sample_analysis):
        print(" Payload analysis sent to Splunk")
    print()

    # Create security alert
    alert_data = {
        "alert_type": "critical_xss_detected",
        "severity": "critical",
        "title": "Critical XSS Vulnerability Detected",
        "description": "Multiple XSS vulnerabilities found in web application",
        "context": "html_content",
        "cvss_score": 8.8,
        "affected_systems": ["web_application", "user_sessions"],
        "immediate_actions": [
            "Block malicious requests",
            "Implement input sanitization",
            "Deploy CSP headers",
            "Security team review required",
        ],
        "alert_id": "brs_kb_critical_001",
        "escalation_required": True,
    }

    if connector.send_security_alert(alert_data):
        print("🚨 Security alert sent to Splunk")
    print()

    # Show example search queries
    print("🔍 Example Splunk Search Queries:")
    print("-" * 40)

    queries = connector.get_dashboard_queries()

    for name, query in queries.items():
        print(f"{name}:")
        print(f"   {query.strip()}")
        print()

    print(" BRS-KB Splunk integration demonstration complete!")
    print("Ready for production SIEM integration.")

    return 0


if __name__ == "__main__":
    exit(main())

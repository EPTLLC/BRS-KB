#!/usr/bin/env python3

"""
BRS-KB Graylog Integration Connector
Project: BRS-KB (BRS XSS Knowledge Base)
Company: EasyProTech LLC (www.easyprotech)
Dev: Brabus
Date: Sat 25 Oct 2025 12:00:00 UTC
Status: Created
Telegram: https://t.me/easyprotech

Graylog GELF integration for BRS-KB XSS vulnerability data ingestion and alerting
"""

import json
import socket
import time
from datetime import datetime
from typing import Any, Dict, List

import requests


# Version from single source
try:
    from brs_kb.version import __version__ as BRS_KB_VERSION
except ImportError:
    BRS_KB_VERSION = "4.0.0"  # Fallback for standalone use


class BRSKBGraylogConnector:
    """BRS-KB Graylog integration for log ingestion and alerting"""

    def __init__(self, graylog_url: str, gelf_port: int = 12201, facility: str = "brs-kb-security"):
        """
        Initialize Graylog connector

        Args:
            graylog_url: Graylog server URL (e.g., https://graylog.company.com)
            gelf_port: GELF UDP port (default: 12201)
            facility: Log facility name
        """
        self.graylog_url = graylog_url.rstrip("/")
        self.gelf_port = gelf_port
        self.facility = facility

        # Create UDP socket for GELF
        self.gelf_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    def send_gelf_log(self, log_data: Dict[str, Any], level: int = 6) -> bool:
        """
        Send log data to Graylog via GELF

        Args:
            log_data: Log data to send
            level: Log level (0=Emergency, 1=Alert, 2=Critical, 3=Error, 4=Warning, 5=Notice, 6=Info, 7=Debug)

        Returns:
            bool: Success status
        """
        try:
            # Format GELF message
            gelf_message = self._format_gelf_message(log_data, level)

            # Send via UDP
            self.gelf_socket.sendto(
                json.dumps(gelf_message).encode("utf-8"),
                (self.graylog_url.replace("https://", "").replace("http://", ""), self.gelf_port),
            )

            print(f" GELF log sent to Graylog: {log_data.get('short_message', 'BRS-KB log')}")
            return True

        except Exception as e:
            print(f" Error sending GELF log to Graylog: {e}")
            return False

    def send_vulnerability_log(self, vulnerability_data: Dict[str, Any]) -> bool:
        """
        Send XSS vulnerability log to Graylog

        Args:
            vulnerability_data: Vulnerability information from BRS-KB

        Returns:
            bool: Success status
        """
        log_data = {
            "short_message": f"XSS Vulnerability Detected: {vulnerability_data.get('context', 'unknown')}",
            "full_message": self._format_full_vulnerability_message(vulnerability_data),
            "facility": self.facility,
            "level": 3,  # Error level for vulnerabilities
            "_event_type": "xss_vulnerability",
            "_source": "brs_kb",
            "_context": vulnerability_data.get("context", "unknown"),
            "_severity": vulnerability_data.get("severity", "unknown"),
            "_cvss_score": vulnerability_data.get("cvss_score", 0.0),
            "_payload": vulnerability_data.get("payload", ""),
            "_cwe": vulnerability_data.get("cwe", []),
            "_owasp": vulnerability_data.get("owasp", []),
            "_tags": vulnerability_data.get("tags", []),
            "_browser_support": vulnerability_data.get("browser_support", []),
            "_waf_evasion": vulnerability_data.get("waf_evasion", False),
            "_confidence": vulnerability_data.get("confidence", 0.0),
            "_remediation": vulnerability_data.get("remediation", ""),
        }

        return self.send_gelf_log(log_data, 3)  # Error level

    def send_payload_analysis_log(self, analysis_data: Dict[str, Any]) -> bool:
        """
        Send payload analysis log to Graylog

        Args:
            analysis_data: Payload analysis from BRS-KB

        Returns:
            bool: Success status
        """
        log_data = {
            "short_message": f"Payload Analysis: {analysis_data.get('payload', 'unknown')[:50]}...",
            "full_message": self._format_full_analysis_message(analysis_data),
            "facility": self.facility,
            "level": 6,  # Info level for analysis
            "_event_type": "payload_analysis",
            "_source": "brs_kb",
            "_payload": analysis_data.get("payload", ""),
            "_contexts": analysis_data.get("contexts", []),
            "_severity": analysis_data.get("severity", "unknown"),
            "_confidence": analysis_data.get("confidence", 0.0),
            "_effectiveness": analysis_data.get("effectiveness_score", 0.0),
            "_risk_level": analysis_data.get("risk_level", "unknown"),
            "_waf_detected": analysis_data.get("waf_detected", []),
            "_recommendations": analysis_data.get("recommendations", []),
        }

        return self.send_gelf_log(log_data, 6)  # Info level

    def send_security_alert(self, alert_data: Dict[str, Any]) -> bool:
        """
        Send security alert to Graylog

        Args:
            alert_data: Alert information

        Returns:
            bool: Success status
        """
        severity_map = {
            "critical": 2,  # Critical
            "high": 3,  # Error
            "medium": 4,  # Warning
            "low": 6,  # Info
        }

        level = severity_map.get(alert_data.get("severity", "medium"), 4)

        log_data = {
            "short_message": f"Security Alert: {alert_data.get('title', 'BRS-KB Alert')}",
            "full_message": self._format_full_alert_message(alert_data),
            "facility": self.facility,
            "level": level,
            "_event_type": "security_alert",
            "_source": "brs_kb",
            "_alert_type": alert_data.get("alert_type", "unknown"),
            "_severity": alert_data.get("severity", "medium"),
            "_title": alert_data.get("title", ""),
            "_description": alert_data.get("description", ""),
            "_context": alert_data.get("context", ""),
            "_cvss_score": alert_data.get("cvss_score", 0.0),
            "_affected_systems": alert_data.get("affected_systems", []),
            "_immediate_actions": alert_data.get("immediate_actions", []),
            "_escalation_required": alert_data.get("escalation_required", False),
        }

        return self.send_gelf_log(log_data, level)

    def _format_gelf_message(self, log_data: Dict[str, Any], level: int) -> Dict[str, Any]:
        """Format log data as GELF message"""
        return {
            "version": "1.1",
            "host": "brs-kb",
            "short_message": log_data.get("short_message", "BRS-KB log message"),
            "full_message": log_data.get("full_message", ""),
            "timestamp": time.time(),
            "level": level,
            "facility": log_data.get("facility", self.facility),
            "_event_type": log_data.get("_event_type", "unknown"),
            "_source": log_data.get("_source", "brs_kb"),
            **{k: v for k, v in log_data.items() if k.startswith("_")},
        }

    def _format_full_vulnerability_message(self, vulnerability_data: Dict[str, Any]) -> str:
        """Format detailed vulnerability message"""
        return f"""
XSS Vulnerability Detected

Context: {vulnerability_data.get('context', 'unknown')}
Severity: {vulnerability_data.get('severity', 'unknown').upper()}
CVSS Score: {vulnerability_data.get('cvss_score', 0.0)}
Confidence: {vulnerability_data.get('confidence', 0.0)}

Payload: {vulnerability_data.get('payload', '')}

Description: {vulnerability_data.get('description', '')}

Remediation: {vulnerability_data.get('remediation', '')}

CWE: {', '.join(vulnerability_data.get('cwe', []))}
OWASP: {', '.join(vulnerability_data.get('owasp', []))}
Tags: {', '.join(vulnerability_data.get('tags', []))}

Browser Support: {', '.join(vulnerability_data.get('browser_support', []))}
WAF Evasion: {vulnerability_data.get('waf_evasion', False)}
Analysis Method: {vulnerability_data.get('analysis_method', 'unknown')}

Timestamp: {datetime.now().isoformat()}
Source: BRS-KB v{BRS_KB_VERSION}
"""

    def _format_full_analysis_message(self, analysis_data: Dict[str, Any]) -> str:
        """Format detailed analysis message"""
        return f"""
Payload Analysis Results

Payload: {analysis_data.get('payload', '')}
Contexts: {', '.join(analysis_data.get('contexts', []))}
Severity: {analysis_data.get('severity', 'unknown').upper()}
Confidence: {analysis_data.get('confidence', 0.0)}
Effectiveness: {analysis_data.get('effectiveness_score', 0.0)}
Risk Level: {analysis_data.get('risk_level', 'unknown').upper()}

Analysis Method: {analysis_data.get('analysis_method', 'unknown')}

Browser Parsing:
{json.dumps(analysis_data.get('browser_parsing', {}), indent=2)}

WAF Detection: {', '.join(analysis_data.get('waf_detected', []))}

Recommendations:
{chr(10).join(f'• {rec}' for rec in analysis_data.get('recommendations', []))}

Timestamp: {datetime.now().isoformat()}
Source: BRS-KB v{BRS_KB_VERSION}
"""

    def _format_full_alert_message(self, alert_data: Dict[str, Any]) -> str:
        """Format detailed alert message"""
        return f"""
Security Alert

Alert Type: {alert_data.get('alert_type', 'unknown')}
Severity: {alert_data.get('severity', 'unknown').upper()}
Title: {alert_data.get('title', '')}
Description: {alert_data.get('description', '')}

Context: {alert_data.get('context', '')}
CVSS Score: {alert_data.get('cvss_score', 0.0)}

Affected Systems: {', '.join(alert_data.get('affected_systems', []))}

Immediate Actions Required:
{chr(10).join(f'• {action}' for action in alert_data.get('immediate_actions', []))}

Escalation Required: {alert_data.get('escalation_required', False)}

Timestamp: {datetime.now().isoformat()}
Source: BRS-KB v{BRS_KB_VERSION}
Alert ID: {alert_data.get('alert_id', 'unknown')}
"""

    def create_graylog_dashboard(self, dashboard_name: str = "BRS-KB XSS Dashboard") -> bool:
        """
        Create Graylog dashboard for BRS-KB data visualization

        Args:
            dashboard_name: Name for the dashboard

        Returns:
            bool: Success status
        """
        try:
            # Create dashboard configuration
            dashboard_config = {
                "title": dashboard_name,
                "description": "BRS-KB XSS vulnerability analysis dashboard",
                "widgets": [
                    {
                        "type": "AGGREGATION",
                        "config": {
                            "query": "_event_type:xss_vulnerability",
                            "timerange": {"type": "relative", "range": 86400},
                            "aggregation": {"type": "terms", "field": "_context"},
                            "visualization": {"type": "bar"},
                        },
                    },
                    {
                        "type": "AGGREGATION",
                        "config": {
                            "query": "_event_type:xss_vulnerability",
                            "timerange": {"type": "relative", "range": 86400},
                            "aggregation": {"type": "terms", "field": "_severity"},
                            "visualization": {"type": "pie"},
                        },
                    },
                ],
            }

            # Send to Graylog API
            response = requests.post(
                f"{self.graylog_url}/api/dashboards", json=dashboard_config, timeout=30
            )

            if response.status_code in [200, 201]:
                print(f" Graylog dashboard created: {dashboard_name}")
                return True
            else:
                print(f" Failed to create dashboard: {response.status_code}")
                return False

        except Exception as e:
            print(f" Error creating dashboard: {e}")
            return False

    def create_alert_rule(self, rule_name: str = "BRS-KB Critical XSS Alert") -> bool:
        """
        Create Graylog alert rule for critical XSS vulnerabilities

        Args:
            rule_name: Name for the alert rule

        Returns:
            bool: Success status
        """
        try:
            rule_config = {
                "title": rule_name,
                "description": "Alert for critical XSS vulnerabilities detected by BRS-KB",
                "condition": {
                    "type": "aggregation",
                    "query": "_event_type:xss_vulnerability AND _cvss_score:>=7.0",
                    "timerange": {"type": "relative", "range": 300},  # 5 minutes
                    "aggregation": {"type": "count", "field": "_context"},
                    "threshold": 1,
                    "threshold_type": "more",
                },
                "notification_settings": {"grace_period_ms": 0, "backlog_size": 100},
            }

            response = requests.post(
                f"{self.graylog_url}/api/events/notifications", json=rule_config, timeout=30
            )

            if response.status_code in [200, 201]:
                print(f" Alert rule created: {rule_name}")
                return True
            else:
                print(f" Failed to create alert rule: {response.status_code}")
                return False

        except Exception as e:
            print(f" Error creating alert rule: {e}")
            return False

    def test_connection(self) -> bool:
        """Test connection to Graylog"""
        try:
            response = requests.get(f"{self.graylog_url}/api/system", timeout=10)
            return response.status_code == 200
        except Exception:
            return False


def create_sample_graylog_data() -> List[Dict[str, Any]]:
    """Create sample data for Graylog testing"""
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
    ]


def main():
    """Main function for testing and demonstration"""
    print("BRS-KB Graylog Integration Connector")
    print("=" * 50)
    print()

    # Configuration
    graylog_url = "https://your-graylog.company.com"
    gelf_port = 12201
    facility = "brs-kb-security"

    # Initialize connector
    connector = BRSKBGraylogConnector(graylog_url, gelf_port, facility)

    print(" Connector initialized")
    print(f" Graylog URL: {graylog_url}")
    print(f"🔌 GELF Port: {gelf_port}")
    print(f" Facility: {facility}")
    print()

    # Test connection
    if connector.test_connection():
        print(" Graylog connection successful")
    else:
        print(" Graylog connection failed")
        print("Please verify your Graylog configuration")
        return 1

    print()

    # Send sample vulnerability data
    print("📤 Sending sample vulnerability logs...")

    sample_data = create_sample_graylog_data()
    sent_count = 0

    for vuln_data in sample_data:
        if connector.send_vulnerability_log(vuln_data):
            sent_count += 1

    print(f" Sent {sent_count}/{len(sample_data)} vulnerability logs")
    print()

    # Create dashboard
    print(" Creating Graylog dashboard...")
    if connector.create_graylog_dashboard("BRS-KB XSS Analysis Dashboard"):
        print(" Graylog dashboard created")
    print()

    # Create alert rule
    print("🚨 Creating alert rule...")
    if connector.create_alert_rule("BRS-KB Critical XSS Alert"):
        print(" Alert rule created")
    print()

    print(" BRS-KB Graylog integration demonstration complete!")
    print("Ready for production SIEM integration.")

    return 0


if __name__ == "__main__":
    exit(main())

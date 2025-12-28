#!/usr/bin/env python3

"""
Project: BRS-KB (BRS XSS Knowledge Base)
Company: EasyProTech LLC (www.easyprotech)
Dev: Brabus
Date: Sat 25 Oct 2025 12:00:00 UTC
Status: Created
Telegram: https://t.me/easyprotech

Payload Testing API: Automated XSS Payload Testing and Validation
Testing framework for XSS payloads with browser simulation and WAF detection
"""

import re
from typing import Any, Dict, List

from brs_kb.payloads import PAYLOAD_DATABASE


class PayloadTester:
    """Advanced XSS payload testing framework"""

    def __init__(self):
        self.test_results = {}
        self.waf_patterns = self._load_waf_patterns()

    def _load_waf_patterns(self) -> Dict[str, List[str]]:
        """Load WAF detection patterns"""
        return {
            "mod_security": [
                r"ModSecurity",
                r"mod_security",
                r"ModSecurity Rules",
                r"Request Denied",
            ],
            "cloudflare": [
                r"Cloudflare",
                r"Ray ID",
                r"Attention Required",
                r"Checking your browser",
            ],
            "aws_waf": [r"AWS WAF", r"Blocked by AWS WAF", r"Forbidden: Access Denied"],
            "akamai": [r"Akamai", r"Access Denied", r"Reference ID"],
        }

    def test_payload_in_context(self, payload: str, context: str) -> Dict[str, Any]:
        """Test payload effectiveness in specific context"""
        # Simulate browser parsing
        browser_result = self._simulate_browser_parsing(payload, context)

        # Check WAF detection
        waf_detected = self._detect_waf_blockage(payload)

        # Calculate effectiveness score
        effectiveness = self._calculate_effectiveness(payload, context, browser_result)

        return {
            "payload": payload,
            "context": context,
            "browser_parsing": browser_result,
            "waf_detected": waf_detected,
            "effectiveness_score": effectiveness,
            "risk_level": self._get_risk_level(effectiveness),
            "recommendations": self._get_recommendations(payload, context, effectiveness),
        }

    def _simulate_browser_parsing(self, payload: str, context: str) -> Dict[str, Any]:
        """Simulate how browser would parse the payload"""
        result = {
            "script_execution": False,
            "html_injection": False,
            "event_execution": False,
            "css_injection": False,
            "parsing_errors": [],
        }

        # Check for script execution
        if re.search(r"<script[^>]*>.*?</script>", payload, re.IGNORECASE):
            result["script_execution"] = True

        # Check for HTML injection
        if re.search(r"<[^>]*>", payload):
            result["html_injection"] = True

        # Check for event handlers
        if re.search(r"on\w+\s*=", payload):
            result["event_execution"] = True

        # Check for CSS injection
        if re.search(r"(background|src)\s*:\s*[^;]+", payload):
            result["css_injection"] = True

        return result

    def _detect_waf_blockage(self, payload: str) -> List[str]:
        """Detect potential WAF blockage patterns"""
        detected_wafs = []

        for waf_name, patterns in self.waf_patterns.items():
            for pattern in patterns:
                if re.search(pattern, payload, re.IGNORECASE):
                    detected_wafs.append(waf_name)

        return detected_wafs

    def _calculate_effectiveness(self, payload: str, context: str, browser_result: Dict) -> float:
        """Calculate payload effectiveness score (0.0-1.0)"""
        score = 0.0

        # Base score from browser parsing
        if browser_result["script_execution"]:
            score += 0.4
        if browser_result["html_injection"]:
            score += 0.3
        if browser_result["event_execution"]:
            score += 0.3
        if browser_result["css_injection"]:
            score += 0.2

        # Context-specific bonuses
        if context in ["html_content", "javascript"]:
            score *= 1.2
        elif context in ["template_injection", "dom_xss"]:
            score *= 1.1

        # WAF bypass capability
        if any(char in payload for char in ["<", ">", '"', "'"]):
            score *= 1.1  # Likely to be filtered

        return min(score, 1.0)

    def _get_risk_level(self, effectiveness: float) -> str:
        """Get risk level based on effectiveness score"""
        if effectiveness >= 0.8:
            return "critical"
        elif effectiveness >= 0.6:
            return "high"
        elif effectiveness >= 0.4:
            return "medium"
        else:
            return "low"

    def _get_recommendations(self, payload: str, context: str, effectiveness: float) -> List[str]:
        """Get security recommendations"""
        recommendations = []

        if effectiveness >= 0.8:
            recommendations.append(
                "CRITICAL: This payload is highly effective - implement strict input validation"
            )
            recommendations.append("Consider implementing Content Security Policy (CSP)")

        if "<script" in payload.lower():
            recommendations.append("Block or sanitize script tags in user input")

        if "javascript:" in payload.lower():
            recommendations.append("Validate and sanitize URL inputs")

        if "on" in payload.lower() and "=" in payload:
            recommendations.append("Block or sanitize event handlers")

        if context in ["html_content", "html_attribute"]:
            recommendations.append("Use HTML entity encoding for output")

        if context in ["javascript", "js_string"]:
            recommendations.append("Use JSON serialization for JavaScript variables")

        return recommendations


def test_all_payloads() -> Dict[str, Any]:
    """Test all payloads in database"""
    tester = PayloadTester()
    results = {}

    for payload_id, payload_entry in PAYLOAD_DATABASE.items():
        context_results = {}

        for context in payload_entry.contexts:
            test_result = tester.test_payload_in_context(payload_entry.payload, context)
            context_results[context] = test_result

        results[payload_id] = {
            "payload_info": payload_entry,
            "test_results": context_results,
            "overall_effectiveness": max(
                r["effectiveness_score"] for r in context_results.values()
            ),
        }

    return results


def validate_payload_database() -> Dict[str, Any]:
    """Validate payload database integrity"""
    validation_results: Dict[str, Any] = {
        "total_payloads": len(PAYLOAD_DATABASE),
        "contexts_covered": set(),
        "severities_found": set(),
        "tags_found": set(),
        "waf_bypass_count": 0,
        "errors": [],
    }

    for payload_id, payload in PAYLOAD_DATABASE.items():
        # Validate payload structure
        if not payload.payload or not payload.contexts:
            validation_results["errors"].append(f"Invalid payload: {payload_id}")

        # Collect statistics
        validation_results["contexts_covered"].update(payload.contexts)
        validation_results["severities_found"].add(payload.severity)
        validation_results["tags_found"].update(payload.tags)

        if payload.waf_evasion:
            validation_results["waf_bypass_count"] += 1

    validation_results["contexts_covered"] = sorted(validation_results["contexts_covered"])
    validation_results["severities_found"] = sorted(validation_results["severities_found"])
    validation_results["tags_found"] = sorted(validation_results["tags_found"])

    return validation_results


def generate_payload_report() -> str:
    """Generate comprehensive payload analysis report"""
    validation = validate_payload_database()

    report = []
    report.append("BRS-KB Payload Database Analysis Report")
    report.append("=" * 50)
    report.append(f"Generated: {__import__('datetime').datetime.now().isoformat()}")
    report.append("")

    report.append("DATABASE STATISTICS:")
    report.append(f"Total payloads: {validation['total_payloads']}")
    report.append(f"Contexts covered: {len(validation['contexts_covered'])}")
    report.append(f"Severities: {len(validation['severities_found'])} levels")
    report.append(f"WAF bypass payloads: {validation['waf_bypass_count']}")
    report.append(f"Total tags: {len(validation['tags_found'])}")
    report.append("")

    report.append("CONTEXT COVERAGE:")
    for context in validation["contexts_covered"]:
        payload_count = len([p for p in PAYLOAD_DATABASE.values() if context in p.contexts])
        report.append(f"  {context}: {payload_count} payloads")
    report.append("")

    # Show top risk payloads from database
    from brs_kb.payloads import get_payloads_by_severity

    critical_payloads = get_payloads_by_severity("critical")

    report.append("TOP CRITICAL PAYLOADS:")
    for i, payload in enumerate(critical_payloads[:10], 1):
        report.append(f"  {i}. {payload.payload[:50]}...")
        report.append(f"     CVSS: {payload.cvss_score}")
        report.append(f"     Contexts: {', '.join(payload.contexts)}")
        report.append(f"     WAF Evasion: {'Yes' if payload.waf_evasion else 'No'}")
        report.append("")

    if validation["errors"]:
        report.append("VALIDATION ERRORS:")
        for error in validation["errors"]:
            report.append(f"  - {error}")
        report.append("")

    return "\n".join(report)


def find_best_payloads_for_context(
    context: str, min_effectiveness: float = 0.5
) -> List[Dict[str, Any]]:
    """Find best payloads for a specific context"""
    tester = PayloadTester()
    results = []

    relevant_payloads = [
        payload for payload in PAYLOAD_DATABASE.values() if context in payload.contexts
    ]

    for payload in relevant_payloads:
        test_result = tester.test_payload_in_context(payload.payload, context)

        if test_result["effectiveness_score"] >= min_effectiveness:
            results.append(
                {
                    "payload_id": (
                        payload.payload[:50] + "..."
                        if len(payload.payload) > 50
                        else payload.payload
                    ),
                    "payload": payload.payload,
                    "effectiveness": test_result["effectiveness_score"],
                    "risk_level": test_result["risk_level"],
                    "waf_evasion": payload.waf_evasion,
                    "tags": payload.tags,
                    "description": payload.description,
                }
            )

    # Sort by effectiveness
    results.sort(key=lambda x: x["effectiveness"], reverse=True)
    return results


# Export functions
__all__ = [
    "PayloadTester",
    "find_best_payloads_for_context",
    "generate_payload_report",
    "test_all_payloads",
    "validate_payload_database",
]

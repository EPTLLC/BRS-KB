#!/usr/bin/env python3

"""
Project: BRS-KB (BRS XSS Knowledge Base)
Company: EasyProTech LLC (www.easyprotech)
Dev: Brabus
Date: Sat 25 Oct 2025 12:00:00 UTC
Status: Created
Telegram: https://t.me/easyprotech

Example: BRS-KB Integrated Demo - Complete XSS Intelligence Platform
Demonstrates the complete integration of contexts, reverse mapping, and payload database
"""

from brs_kb import (
    get_kb_info,
    list_contexts,
    get_vulnerability_details,
    get_payloads_by_context,
    get_database_info,
    test_payload_in_context,
    find_best_payloads_for_context,
    get_waf_bypass_payloads
)
from brs_kb.reverse_map import find_contexts_for_payload


def demonstrate_complete_system():
    """Demonstrate the complete BRS-KB system capabilities."""

    print("=" * 90)
    print("🚀 BRS-KB Complete XSS Intelligence Platform")
    print("=" * 90)
    print()

    # System overview
    kb_info = get_kb_info()
    db_info = get_database_info()

    print("📊 SYSTEM OVERVIEW:")
    print(f"   • XSS Contexts: {kb_info['total_contexts']}")
    print(f"   • Payload Database: {db_info['total_payloads']} payloads")
    print(f"   • WAF Bypass: {db_info['waf_bypass_count']} payloads")
    print(f"   • Browser Support: {len(db_info['browser_support'])} browsers")
    print()

    # Modern XSS contexts demonstration
    print("🔥 MODERN XSS CONTEXTS:")
    print("-" * 50)

    modern_contexts = ['websocket_xss', 'service_worker_xss', 'webrtc_xss', 'graphql_xss', 'shadow_dom_xss']

    for context in modern_contexts:
        details = get_vulnerability_details(context)
        payloads = get_payloads_by_context(context)

        print(f"📍 {context.upper()}")
        print(f"   Description: {details['description'][:80]}...")
        print(f"   Severity: {details['severity'].upper()} (CVSS: {details['cvss_score']})")
        print(f"   Payloads: {len(payloads)} available")
        print(f"   Defenses: {len([d['defense'] for d in details.get('defenses', [])])} recommended")
        print()

    # Payload analysis demonstration
    print("🔍 PAYLOAD ANALYSIS & TESTING:")
    print("-" * 50)

    test_payloads = [
        ("<script>alert('XSS')</script>", "Classic script injection"),
        ("javascript:alert(1)", "Protocol injection"),
        ('{"type": "chat", "message": "<script>alert(1)</script>"}', "WebSocket message"),
        ("{{constructor.constructor('alert(1)')()}}", "Template injection"),
        ('<my-component><script>alert(1)</script></my-component>', "Custom elements")
    ]

    for payload, description in test_payloads:
        print(f"🎯 {description}")
        print(f"   Payload: {payload}")

        # Reverse mapping analysis
        analysis = find_contexts_for_payload(payload)
        print(f"   → Contexts: {', '.join(analysis['contexts'])}")
        print(f"   → Confidence: {analysis['confidence']}")
        print(f"   → Method: {analysis['analysis_method']}")

        # Payload testing
        if analysis['contexts']:
            test_result = test_payload_in_context(payload, analysis['contexts'][0])
            print(f"   → Effectiveness: {test_result['effectiveness_score']}")
            print(f"   → Risk Level: {test_result['risk_level']}")

        print()

    # Best payloads for security testing
    print("🧪 BEST PAYLOADS FOR TESTING:")
    print("-" * 50)

    test_contexts = ['html_content', 'websocket_xss', 'graphql_xss']

    for context in test_contexts:
        best_payloads = find_best_payloads_for_context(context, min_effectiveness=0.8)

        if best_payloads:
            print(f"🎖️ {context}: Top payloads for testing")
            for i, payload_info in enumerate(best_payloads[:2], 1):
                print(f"   {i}. {payload_info['payload'][:50]}...")
                print(f"      Effectiveness: {payload_info['effectiveness']}")
                print(f"      Risk: {payload_info['risk_level']}")
                print(f"      WAF Evasion: {'Yes' if payload_info['waf_evasion'] else 'No'}")
            print()

    # WAF bypass techniques
    print("🛡️ WAF BYPASS TECHNIQUES:")
    print("-" * 50)

    waf_payloads = get_waf_bypass_payloads()

    for i, payload_info in enumerate(waf_payloads[:3], 1):
        print(f"🚨 {i}. {payload_info['payload'][:50]}...")
        print(f"   Contexts: {', '.join(payload_info['contexts'])}")
        print(f"   Severity: {payload_info['severity']}")
        print(f"   Tags: {', '.join(payload_info['tags'][:3])}")
        print()

    # Security recommendations
    print("💡 SECURITY RECOMMENDATIONS:")
    print("-" * 50)

    recommendations = [
        "1. Implement Content Security Policy (CSP) with strict settings",
        "2. Use HTML entity encoding for all user-generated content",
        "3. Validate and sanitize all inputs server-side",
        "4. Implement WebSocket message sanitization",
        "5. Use secure coding practices for modern frameworks",
        "6. Regular security testing with comprehensive payload sets",
        "7. Monitor for WAF bypass attempts",
        "8. Keep dependencies updated and secure"
    ]

    for rec in recommendations:
        print(f"   {rec}")

    print()
    print("=" * 90)
    print("✨ BRS-KB: Complete XSS Intelligence Solution")
    print("   Ready for enterprise security testing and vulnerability assessment")
    print("=" * 90)


if __name__ == "__main__":
    demonstrate_complete_system()

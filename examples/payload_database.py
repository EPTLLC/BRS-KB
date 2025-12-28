#!/usr/bin/env python3

"""
Project: BRS-KB (BRS XSS Knowledge Base)
Company: EasyProTech LLC (www.easyprotech)
Dev: Brabus
Date: Sat 25 Oct 2025 12:00:00 UTC
Status: Created
Telegram: https://t.me/easyprotech

Example: BRS-KB Payload Database - XSS Payload Collection and Testing
Demonstrates comprehensive payload database with 50+ categorized payloads
"""

from brs_kb import (
    find_best_payloads_for_context,
    get_database_info,
    get_payloads_by_context,
    get_payloads_by_severity,
    get_waf_bypass_payloads,
    search_payloads,
    test_payload_in_context,
)


def main():
    """Demonstrate payload database capabilities."""

    print("=" * 80)
    print("BRS-KB Payload Database Demo")
    print("=" * 80)
    print()

    # Show database information
    print("1. Payload Database Information:")
    print("-" * 80)
    db_info = get_database_info()
    print(f"Total payloads: {db_info['total_payloads']}")
    print(f"Contexts covered: {len(db_info['contexts_covered'])}")
    print(f"WAF bypass payloads: {db_info['waf_bypass_count']}")
    print(f"Total tags: {len(db_info['tags'])}")
    print(f"Browser support: {len(db_info['browser_support'])} browsers")
    print()

    # Show payloads by context
    print("2. Payloads by Context:")
    print("-" * 80)
    contexts_to_show = ["html_content", "javascript", "websocket"]

    for context in contexts_to_show:
        payloads = get_payloads_by_context(context)
        print(f"{context}: {len(payloads)} payloads")

        if payloads:
            # Show top 2 payloads
            for i, payload in enumerate(payloads[:2], 1):
                print(f"  {i}. {payload['payload'][:60]}...")
                print(f"     Severity: {payload['severity']} (CVSS: {payload['cvss_score']})")
                print(f"     Tags: {', '.join(payload['tags'][:3])}")
        print()

    # Show payloads by severity
    print("3. High-Severity Payloads:")
    print("-" * 80)
    critical_payloads = get_payloads_by_severity("critical")

    for i, payload in enumerate(critical_payloads[:5], 1):
        print(f"{i}. {payload['payload'][:50]}...")
        print(f"   Contexts: {', '.join(payload['contexts'])}")
        print(f"   CVSS: {payload['cvss_score']}")
        print(f"   WAF Evasion: {'Yes' if payload['waf_evasion'] else 'No'}")
        print()

    # Search functionality
    print("4. Payload Search:")
    print("-" * 80)
    search_queries = ["script", "websocket", "bypass", "polyglot"]

    for query in search_queries:
        results = search_payloads(query)
        print(f"Search '{query}': {len(results)} results")

        if results:
            best_result = results[0]
            print(f"  Best match: {best_result['payload'][:50]}...")
            print(f"  Relevance: {best_result['relevance_score']}")
            print(f"  Contexts: {', '.join(best_result['contexts'])}")
        print()

    # WAF bypass payloads
    print("5. WAF Bypass Payloads:")
    print("-" * 80)
    waf_payloads = get_waf_bypass_payloads()

    for i, payload in enumerate(waf_payloads[:3], 1):
        print(f"{i}. {payload['payload'][:50]}...")
        print(f"   Contexts: {', '.join(payload['contexts'])}")
        print(f"   Tags: {', '.join(payload['tags'])}")
        print()

    # Best payloads for specific contexts
    print("6. Best Payloads for Modern Contexts:")
    print("-" * 80)
    modern_contexts = ["websocket", "graphql", "service_worker"]

    for context in modern_contexts:
        best_payloads = find_best_payloads_for_context(context, min_effectiveness=0.7)
        print(f"{context}: {len(best_payloads)} effective payloads")

        if best_payloads:
            top_payload = best_payloads[0]
            print(f"  Top: {top_payload['payload'][:50]}...")
            print(f"  Effectiveness: {top_payload['effectiveness']}")
            print(f"  Risk: {top_payload['risk_level']}")
        print()

    # Payload testing
    print("7. Payload Testing:")
    print("-" * 80)
    test_payload = "<script>alert('XSS')</script>"
    test_context = "html_content"

    print(f"Testing payload: {test_payload}")
    print(f"Context: {test_context}")
    print()

    test_result = test_payload_in_context(test_payload, test_context)
    print(f"Browser parsing: {test_result['browser_parsing']}")
    print(f"WAF detected: {test_result['waf_detected']}")
    print(f"Effectiveness: {test_result['effectiveness_score']}")
    print(f"Risk level: {test_result['risk_level']}")
    print()

    print("Recommendations:")
    for rec in test_result["recommendations"]:
        print(f"  - {rec}")
    print()

    print("=" * 80)
    print("Payload database demonstration complete!")
    print("Ready for security testing and vulnerability assessment.")
    print("=" * 80)


if __name__ == "__main__":
    main()

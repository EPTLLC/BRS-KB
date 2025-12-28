#!/usr/bin/env python3

"""
Project: BRS-KB (BRS XSS Knowledge Base)
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: Sat 25 Oct 2025 12:00:00 UTC
Status: Enhanced
Telegram: https://t.me/easyprotech

Example: Enhanced Reverse Mapping - Automatic Context Detection with ML-ready features
"""

from brs_kb.reverse_map import (
    find_contexts_for_payload,
    get_defense_info,
    get_defenses_for_context,
    get_reverse_map_info,
    predict_contexts_ml_ready,
    reverse_lookup,
)


def main():
    """Demonstrate reverse mapping capabilities."""

    print("=" * 80)
    print("BRS-KB Enhanced Reverse Mapping Example")
    print("=" * 80)
    print()

    # Show system information
    info = get_reverse_map_info()
    print(f"System Version: {info['version']}")
    print(f"Total Patterns: {info['total_patterns']}")
    print(f"Supported Contexts: {len(info['supported_contexts'])}")
    print(f"ML Ready: {info['ml_ready']}")
    print()

    # Example 1: Enhanced automatic context detection
    print("1. Enhanced Automatic Context Detection")
    print("-" * 80)

    test_payloads = [
        "<script>alert(1)</script>",
        "javascript:alert(1)",
        'WebSocket("wss://evil.com")',
        '{{constructor.constructor("alert(1)")()}}',
        "<svg onload=alert(1)>",
        "<img src=x onerror=alert(1)>",
    ]

    for payload in test_payloads:
        print(f"Payload: {payload}")
        result = find_contexts_for_payload(payload)

        print(f"  Contexts: {', '.join(result['contexts'])}")
        print(f"  Severity: {result['severity'].upper()}")
        print(f"  Confidence: {result['confidence']}")
        print(f"  Method: {result['analysis_method']}")
        print(f"  Matched patterns: {result['matched_patterns']}")
        print()

    # Example 2: Get defenses for a context
    print("2. Getting Defenses for Context")
    print("-" * 80)

    context = "html_content"
    print(f"Context: {context}")
    print()

    defenses = get_defenses_for_context(context)

    if defenses:
        print("Recommended defenses:")
        for defense in defenses:
            required = "REQUIRED" if defense["required"] else "optional"
            print(f"  [{defense['priority']}] {defense['defense']} ({required})")
    else:
        print("No specific defenses mapped")
    print()

    # Example 3: Get defense implementation details
    print("3. Defense Implementation Details")
    print("-" * 80)

    defense_name = "html_encoding"
    print(f"Defense: {defense_name}")
    print()

    defense_info = get_defense_info(defense_name)

    if defense_info:
        print(f"Effective against: {', '.join(defense_info['effective_against'])}")
        print(f"Bypass difficulty: {defense_info['bypass_difficulty']}")
        print()
        print("Implementation examples:")
        for impl in defense_info["implementation"]:
            print(f"  - {impl}")
    else:
        print("No information available")
    print()

    # Example 4: Universal reverse lookup
    print("4. Universal Reverse Lookup")
    print("-" * 80)

    # Lookup by payload
    print("Lookup type: payload")
    result = reverse_lookup("payload", "<img src=x onerror=alert(1)>")
    print(f"Contexts: {', '.join(result.get('contexts', []))}")
    print()

    # Lookup by context
    print("Lookup type: context")
    result = reverse_lookup("context", "javascript")
    if result.get("defenses"):
        print("Defenses:")
        for d in result["defenses"]:
            print(f"  - {d['defense']}")
    print()

    # Lookup by defense
    print("Lookup type: defense")
    result = reverse_lookup("defense", "csp")
    print(f"Effective against: {', '.join(result.get('effective_against', []))}")
    print()

    # Example 5: Building a defense strategy
    print("5. Building Defense Strategy for Multiple Contexts")
    print("-" * 80)

    contexts_to_protect = ["html_content", "html_attribute", "javascript"]

    all_defenses = set()
    critical_defenses = set()

    for ctx in contexts_to_protect:
        defenses = get_defenses_for_context(ctx)
        print(f"\n{ctx}:")
        for defense in defenses:
            all_defenses.add(defense["defense"])
            if defense["required"]:
                critical_defenses.add(defense["defense"])
            status = "[CRITICAL]" if defense["required"] else "[optional]"
            print(f"  {status} {defense['defense']}")

    print()
    print("=" * 80)
    print("DEFENSE STRATEGY SUMMARY")
    print("=" * 80)
    print(f"Critical defenses (must implement): {len(critical_defenses)}")
    for defense in sorted(critical_defenses):
        print(f"  - {defense}")

    print()
    print(f"Optional defenses (recommended): {len(all_defenses - critical_defenses)}")
    for defense in sorted(all_defenses - critical_defenses):
        print(f"  - {defense}")

    # Example 6: ML-Ready analysis with feature extraction
    print("6. ML-Ready Analysis with Feature Extraction")
    print("-" * 80)

    ml_payload = "<script>alert(document.cookie)</script>"
    print(f"Payload: {ml_payload}")
    print()

    ml_result = predict_contexts_ml_ready(ml_payload)
    print(f"Contexts: {', '.join(ml_result['contexts'])}")
    print(f"Severity: {ml_result['severity']}")
    print(f"Confidence: {ml_result['confidence']}")
    print(f"ML Ready: {ml_result['ml_ready']}")
    print()

    print("Extracted features for ML training:")
    features = ml_result["features"]
    for feature, value in features.items():
        print(f"  {feature}: {value}")
    print()

    # Example 7: Pattern-based lookup
    print("7. Pattern-Based Lookup System")
    print("-" * 80)

    # Find all patterns related to script injection
    script_patterns = reverse_lookup("pattern", "script")
    print(f"Found {script_patterns['count']} patterns related to 'script':")
    for pattern in script_patterns["patterns"][:3]:  # Show top 3
        print(f"  Pattern: {pattern['pattern']}")
        print(f"  Contexts: {', '.join(pattern['contexts'])}")
        print(f"  Confidence: {pattern['confidence']}")
        print()

    # Example 8: Modern context defenses
    print("8. Modern Web Context Defenses")
    print("-" * 80)

    modern_contexts = ["websocket", "service_worker", "webrtc", "webgl"]

    for context in modern_contexts:
        defenses = get_defenses_for_context(context)
        print(f"{context}:")
        for defense in defenses:
            tags = ", ".join(defense.get("tags", []))
            required = "REQUIRED" if defense["required"] else "optional"
            print(f"  [{defense['priority']}] {defense['defense']} ({required}) - {tags}")
        print()

    print("=" * 80)
    print("Enhanced reverse mapping demonstration complete!")
    print("New features: automatic detection, confidence scoring, ML-ready data")
    print("=" * 80)


if __name__ == "__main__":
    main()

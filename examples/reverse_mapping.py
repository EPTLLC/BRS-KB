#!/usr/bin/env python3

"""
Project: BRS-KB (BRS XSS Knowledge Base)
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: 2025-10-14 22:53:00 MSK
Status: Created
Telegram: https://t.me/easyprotech

Example: Reverse Mapping - Payload to Context to Defense
"""

from brs_kb.reverse_map import (
    find_contexts_for_payload,
    get_defenses_for_context,
    get_defense_info,
    reverse_lookup
)


def main():
    """Demonstrate reverse mapping capabilities."""
    
    print("=" * 80)
    print("BRS-KB Reverse Mapping Example")
    print("=" * 80)
    print()
    
    # Example 1: Find contexts for a specific payload
    print("1. Finding Contexts for Payload")
    print("-" * 80)
    
    payload = "<script>alert(1)</script>"
    print(f"Payload: {payload}")
    print()
    
    result = find_contexts_for_payload(payload)
    
    if result['contexts']:
        print(f"Effective in contexts: {', '.join(result['contexts'])}")
        print(f"Severity: {result['severity'].upper()}")
        print(f"Defenses needed: {', '.join(result['defenses'])}")
    else:
        print("No specific context mapping found")
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
            required = "REQUIRED" if defense['required'] else "optional"
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
        for impl in defense_info['implementation']:
            print(f"  - {impl}")
    else:
        print("No information available")
    print()
    
    # Example 4: Universal reverse lookup
    print("4. Universal Reverse Lookup")
    print("-" * 80)
    
    # Lookup by payload
    print("Lookup type: payload")
    result = reverse_lookup('payload', '<img src=x onerror=alert(1)>')
    print(f"Contexts: {', '.join(result.get('contexts', []))}")
    print()
    
    # Lookup by context
    print("Lookup type: context")
    result = reverse_lookup('context', 'javascript_context')
    if result.get('defenses'):
        print("Defenses:")
        for d in result['defenses']:
            print(f"  - {d['defense']}")
    print()
    
    # Lookup by defense
    print("Lookup type: defense")
    result = reverse_lookup('defense', 'csp')
    print(f"Effective against: {', '.join(result.get('effective_against', []))}")
    print()
    
    # Example 5: Building a defense strategy
    print("5. Building Defense Strategy for Multiple Contexts")
    print("-" * 80)
    
    contexts_to_protect = ['html_content', 'html_attribute', 'javascript_context']
    
    all_defenses = set()
    critical_defenses = set()
    
    for ctx in contexts_to_protect:
        defenses = get_defenses_for_context(ctx)
        print(f"\n{ctx}:")
        for defense in defenses:
            all_defenses.add(defense['defense'])
            if defense['required']:
                critical_defenses.add(defense['defense'])
            status = "[CRITICAL]" if defense['required'] else "[optional]"
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
    
    print()
    print("=" * 80)
    print("Reverse mapping demonstration complete!")
    print("=" * 80)


if __name__ == "__main__":
    main()


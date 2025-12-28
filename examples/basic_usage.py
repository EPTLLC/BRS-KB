#!/usr/bin/env python3

"""
Project: BRS-KB (BRS XSS Knowledge Base)
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: 2025-10-14 22:53:00 MSK
Status: Created
Telegram: https://t.me/easyprotech

Example: Basic Usage of BRS-KB
"""

from brs_kb import __version__, get_kb_info, get_vulnerability_details, list_contexts


def main():
    """Demonstrate basic BRS-KB usage."""

    print("=" * 70)
    print("BRS-KB: Community XSS Knowledge Base")
    print(f"Version: {__version__}")
    print("=" * 70)
    print()

    # Get KB information
    print("1. Getting Knowledge Base Information:")
    print("-" * 70)
    kb_info = get_kb_info()
    print(f"Total contexts: {kb_info['total_contexts']}")
    print(f"Build: {kb_info['build']}")
    print(f"Revision: {kb_info['revision']}")
    print()

    # List all available contexts
    print("2. Available Vulnerability Contexts:")
    print("-" * 70)
    contexts = list_contexts()
    for i, context in enumerate(contexts, 1):
        print(f"{i:2d}. {context}")
    print()

    # Get details for specific context
    print("3. HTML Content XSS Details:")
    print("-" * 70)
    details = get_vulnerability_details("html_content")

    print(f"Title: {details['title']}")
    print(f"Severity: {details['severity'].upper()}")
    print(f"CVSS Score: {details['cvss_score']}")
    print(f"CWE: {', '.join(details['cwe'])}")
    print(f"OWASP: {', '.join(details['owasp'])}")
    print()
    print("Description:")
    print(details["description"][:300] + "...")
    print()

    # Get DOM XSS details
    print("4. DOM-based XSS Details:")
    print("-" * 70)
    dom_details = get_vulnerability_details("dom_xss")
    print(f"Title: {dom_details['title']}")
    print(f"Severity: {dom_details.get('severity', 'N/A')}")
    print()
    print("Attack Vector (first 400 chars):")
    print(dom_details["attack_vector"][:400] + "...")
    print()

    # Demonstrate unknown context fallback
    print("5. Unknown Context (Fallback to Default):")
    print("-" * 70)
    unknown = get_vulnerability_details("unknown_context")
    print(f"Title: {unknown.get('title', 'Not available')}")
    print()

    print("=" * 70)
    print("Basic usage demonstration complete!")
    print("Check other examples for advanced usage scenarios.")
    print("=" * 70)


if __name__ == "__main__":
    main()

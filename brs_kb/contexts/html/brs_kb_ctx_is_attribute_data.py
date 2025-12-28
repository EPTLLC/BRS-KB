#!/usr/bin/env python3

"""
Project: BRS-KB (BRS XSS Knowledge Base)
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: 2025-12-27 UTC
Status: Created
Telegram: https://t.me/EasyProTech

is Attribute (Custom Elements) Context - Data Module
"""

DESCRIPTION = """
is attribute allows using custom elements with standard HTML elements.
Vulnerabilities occur when user input is injected into is attributes,
allowing custom element manipulation, behavior override, or XSS attacks.

Vulnerability occurs when:
- User-controlled data is injected into is attribute values
- Custom element names are user-controlled
- Custom element behavior is manipulated
- Element type extension uses user input
- Custom element registration is bypassed

Common injection points:
- is attribute values
- Custom element names
- Custom element constructors
- Element type extension
- Custom element lifecycle hooks
"""

ATTACK_VECTOR = """
1. is attribute injection:
   <div is="USER_INPUT">content</div>

2. Custom element name injection:
   <div is="custom-USER_INPUT">content</div>

3. Element type extension:
   <button is="USER_INPUT">Click</button>

4. Custom element constructor:
   customElements.define(USER_INPUT, class extends HTMLElement {});

5. Element behavior override:
   <input is="USER_INPUT" type="text">

6. Multiple is attributes (invalid):
   <div is="element1" is="USER_INPUT">content</div>
"""

REMEDIATION = """
1. Sanitize all user input before using in is attributes
2. Validate custom element names against allowlist
3. Escape HTML entities in attribute values
4. Use Content Security Policy (CSP)
5. Validate custom element registration
6. Audit all is attribute usage for user input
7. Use framework-safe custom element handling
8. Whitelist allowed custom element names
"""

#!/usr/bin/env python3

"""
Project: BRS-KB (BRS XSS Knowledge Base)
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: 2025-12-27 UTC
Status: Created
Telegram: https://t.me/EasyProTech

ARIA Attributes Context - Data Module
"""

DESCRIPTION = """
ARIA (Accessible Rich Internet Applications) attributes provide accessibility.
Vulnerabilities occur when user input is injected into ARIA attributes,
allowing XSS attacks through attribute manipulation or event handler injection.

Vulnerability occurs when:
- User-controlled data is injected into ARIA attribute values
- ARIA event handlers contain user input
- ARIA role values are user-controlled
- ARIA state properties use user input
- Attribute names are manipulated

Common injection points:
- aria-label attribute
- aria-labelledby attribute
- aria-describedby attribute
- aria-valuetext attribute
- aria-live attribute
- Event handlers in ARIA attributes
"""

ATTACK_VECTOR = """
1. aria-label injection:
   <div aria-label="USER_INPUT">content</div>

2. aria-labelledby injection:
   <div aria-labelledby="USER_INPUT">content</div>

3. aria-describedby injection:
   <div aria-describedby="USER_INPUT">content</div>

4. aria-valuetext injection:
   <div role="slider" aria-valuetext="USER_INPUT"></div>

5. Event handler injection:
   <div aria-label="text" onclick="USER_INPUT">content</div>

6. Role manipulation:
   <div role="USER_INPUT">content</div>
"""

REMEDIATION = """
1. Sanitize all user input before using in ARIA attributes
2. Validate ARIA attribute values
3. Escape HTML entities in attribute values
4. Use Content Security Policy (CSP)
5. Validate ARIA role values against allowlist
6. Never use user input in event handlers
7. Audit all ARIA attribute usage for user input
8. Use framework-safe attribute handling
"""

#!/usr/bin/env python3

"""
Project: BRS-KB (BRS XSS Knowledge Base)
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: 2025-12-27 UTC
Status: Created
Telegram: https://t.me/EasyProTech

CSS Nesting Context - Data Module
"""

DESCRIPTION = """
CSS Nesting allows nesting CSS rules within other rules.
The feature can be exploited for XSS if user input is injected into
nested selectors or CSS properties, allowing CSS injection attacks.

Vulnerability occurs when:
- User-controlled data is injected into nested selectors
- CSS properties contain user input
- Nested rules use user input
- Selector values are user-controlled

Common injection points:
- Nested selector values
- CSS property values
- Pseudo-selectors
- Attribute selectors
- Class and ID selectors
"""

ATTACK_VECTOR = """
1. Selector injection:
   .parent {
       USER_INPUT { color: red; }
   }

2. Property injection:
   .element {
       USER_INPUT: value;
   }

3. Attribute selector injection:
   .element {
       [USER_INPUT] { color: red; }
   }

4. Pseudo-selector injection:
   .element {
       :USER_INPUT { color: red; }
   }

5. Expression injection:
   .element {
       expression(USER_INPUT): value;
   }
"""

REMEDIATION = """
1. Sanitize all user input before using in CSS
2. Validate CSS selectors against allowlist
3. Escape CSS special characters
4. Use Content Security Policy (CSP) with style-src
5. Validate nested rule structures
6. Avoid user input in CSS selectors
7. Use CSS custom properties safely
8. Audit all CSS nesting code for user input
"""

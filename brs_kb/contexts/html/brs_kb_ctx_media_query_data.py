#!/usr/bin/env python3

"""
Project: BRS-KB (BRS XSS Knowledge Base)
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: 2025-12-27 UTC
Status: Created
Telegram: https://t.me/EasyProTech

Media Query Injection Context - Data Module
"""

DESCRIPTION = """
Media queries allow applying styles based on device characteristics.
Vulnerabilities occur when user input is injected into media query conditions,
allowing CSS injection attacks.

Vulnerability occurs when:
- User-controlled data is injected into media query conditions
- Media query features are user-controlled
- Media query values use user input
- CSS injection occurs through media queries
- @media rules contain user input

Common injection points:
- @media rule conditions
- Media feature names
- Media feature values
- Media type values
- Media query expressions
"""

ATTACK_VECTOR = """
1. Media query injection:
   @media (USER_INPUT) {
       body { color: red; }
   }

2. Media feature injection:
   @media (USER_INPUT: value) {
       body { color: red; }
   }

3. Expression injection:
   @media (expression(USER_INPUT)) {
       body { color: red; }
   }

4. Media type injection:
   @media USER_INPUT {
       body { color: red; }
   }

5. Combined injection:
   @media screen and (USER_INPUT) {
       body { color: red; }
   }
"""

REMEDIATION = """
1. Sanitize all user input before using in CSS
2. Validate media query syntax
3. Escape CSS special characters
4. Use Content Security Policy (CSP) with style-src
5. Validate media query conditions
6. Audit all CSS generation code for user input
7. Use framework-safe CSS handling
8. Avoid user input in media queries
"""

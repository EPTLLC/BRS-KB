#!/usr/bin/env python3

"""
Project: BRS-KB (BRS XSS Knowledge Base)
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: 2025-12-27 UTC
Status: Created
Telegram: https://t.me/EasyProTech

CSS Transition Injection Context - Data Module
"""

DESCRIPTION = """
CSS transitions allow smooth property changes.
Vulnerabilities occur when user input is injected into transition properties,
allowing CSS injection attacks.

Vulnerability occurs when:
- User-controlled data is injected into transition properties
- Transition timing functions are user-controlled
- Transition durations use user input
- CSS injection occurs through transitions
- Property names are user-controlled

Common injection points:
- transition-property
- transition-timing-function
- transition-duration
- transition-delay
- Combined transition property
"""

ATTACK_VECTOR = """
1. Property injection:
   transition-property: USER_INPUT;

2. Timing function injection:
   transition-timing-function: USER_INPUT;

3. Expression injection:
   transition: expression(USER_INPUT) 1s;

4. URL injection:
   transition: background url(USER_INPUT) 1s;

5. Combined injection:
   transition: USER_INPUT 1s ease;
"""

REMEDIATION = """
1. Sanitize all user input before using in CSS
2. Validate transition properties against allowlist
3. Escape CSS special characters
4. Use Content Security Policy (CSP) with style-src
5. Validate transition syntax
6. Audit all CSS generation code for user input
7. Use framework-safe CSS handling
8. Avoid user input in transition properties
"""

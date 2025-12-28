#!/usr/bin/env python3

"""
Project: BRS-KB (BRS XSS Knowledge Base)
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: 2025-12-27 UTC
Status: Created
Telegram: https://t.me/EasyProTech

CSS Counters Context - Data Module
"""

DESCRIPTION = """
CSS counters allow automatic numbering of elements.
Vulnerabilities occur when user input is injected into counter names or
counter values, allowing CSS injection attacks.

Vulnerability occurs when:
- User-controlled data is injected into counter names
- Counter values are user-controlled
- counter() function uses user input
- counter-reset or counter-increment use user input
- CSS injection occurs through counters

Common injection points:
- counter-reset property
- counter-increment property
- counter() function
- counters() function
- Counter name values
"""

ATTACK_VECTOR = """
1. Counter name injection:
   counter-reset: USER_INPUT 0;

2. Counter increment injection:
   counter-increment: USER_INPUT;

3. Counter function injection:
   content: counter(USER_INPUT);

4. Counters function injection:
   content: counters(USER_INPUT, ".");

5. Expression injection:
   counter-reset: expression(USER_INPUT);
"""

REMEDIATION = """
1. Sanitize all user input before using in CSS
2. Validate counter names against allowlist
3. Escape CSS special characters
4. Use Content Security Policy (CSP) with style-src
5. Validate CSS counter syntax
6. Audit all CSS generation code for user input
7. Use framework-safe CSS handling
8. Avoid user input in CSS properties
"""

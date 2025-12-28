#!/usr/bin/env python3

"""
Project: BRS-KB (BRS XSS Knowledge Base)
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: 2025-12-27 UTC
Status: Created
Telegram: https://t.me/EasyProTech

CSS Custom Properties Context - Data Module
"""

DESCRIPTION = """
CSS custom properties (variables) allow storing values for reuse.
Vulnerabilities occur when user input is injected into CSS variable names
or values, allowing CSS injection attacks.

Vulnerability occurs when:
- User-controlled data is injected into variable names
- Variable values are user-controlled
- var() function uses user input
- CSS injection occurs through variables
- Variable values contain malicious CSS

Common injection points:
- --variable-name property values
- var() function references
- CSS variable declarations
- Variable value assignments
- calc() with variables
"""

ATTACK_VECTOR = """
1. Variable name injection:
   --USER_INPUT: value;

2. Variable value injection:
   --color: USER_INPUT;

3. var() injection:
   color: var(USER_INPUT);

4. Expression injection:
   --value: expression(USER_INPUT);

5. URL injection:
   --bg: url(USER_INPUT);
"""

REMEDIATION = """
1. Sanitize all user input before using in CSS
2. Validate CSS variable names against allowlist
3. Escape CSS special characters
4. Use Content Security Policy (CSP) with style-src
5. Validate CSS variable syntax
6. Audit all CSS generation code for user input
7. Use framework-safe CSS handling
8. Avoid user input in CSS properties
"""

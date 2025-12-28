#!/usr/bin/env python3

"""
Project: BRS-KB (BRS XSS Knowledge Base)
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: 2025-12-27 UTC
Status: Created
Telegram: https://t.me/EasyProTech

CSS Animation Injection Context - Data Module
"""

DESCRIPTION = """
CSS animations allow creating animated transitions.
Vulnerabilities occur when user input is injected into animation properties
or @keyframes rules, allowing CSS injection attacks.

Vulnerability occurs when:
- User-controlled data is injected into animation names
- Animation properties use user input
- @keyframes rules contain user input
- Animation timing functions are user-controlled
- CSS injection occurs through animations

Common injection points:
- animation-name property
- @keyframes rule names
- animation-timing-function
- animation-duration
- Keyframe percentages
"""

ATTACK_VECTOR = """
1. Animation name injection:
   animation-name: USER_INPUT;

2. @keyframes injection:
   @keyframes USER_INPUT {
       0% { opacity: 0; }
       100% { opacity: 1; }
   }

3. Timing function injection:
   animation-timing-function: USER_INPUT;

4. Expression injection:
   @keyframes anim {
       0% { expression(USER_INPUT): value; }
   }

5. URL injection:
   @keyframes anim {
       0% { background: url(USER_INPUT); }
   }
"""

REMEDIATION = """
1. Sanitize all user input before using in CSS
2. Validate animation names against allowlist
3. Escape CSS special characters
4. Use Content Security Policy (CSP) with style-src
5. Validate @keyframes syntax
6. Audit all CSS generation code for user input
7. Use framework-safe CSS handling
8. Avoid user input in animation properties
"""

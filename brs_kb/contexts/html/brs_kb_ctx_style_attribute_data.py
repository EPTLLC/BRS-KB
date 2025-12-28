#!/usr/bin/env python3

"""
Project: BRS-KB (BRS XSS Knowledge Base)
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: 2025-12-27 UTC
Status: Created
Telegram: https://t.me/EasyProTech

style Attribute Injection Context - Data Module
"""

DESCRIPTION = """
style attribute allows inline CSS styling.
Vulnerabilities occur when user input is injected into style attributes,
allowing CSS injection attacks or XSS through expression() or url() functions.

Vulnerability occurs when:
- User-controlled data is injected into style attribute values
- CSS expressions are user-controlled
- url() functions contain user input
- JavaScript URLs are used in CSS
- CSS injection leads to XSS

Common injection points:
- style attribute values
- CSS property values
- expression() function (IE)
- url() function
- @import in style
- javascript: protocol in CSS
"""

ATTACK_VECTOR = """
1. Style value injection:
   <div style="color: USER_INPUT">content</div>

2. Expression injection (IE):
   <div style="expression(USER_INPUT)">content</div>

3. URL injection:
   <div style="background: url(USER_INPUT)">content</div>

4. JavaScript protocol:
   <div style="background: url('javascript:alert(1)')">content</div>

5. @import injection:
   <div style="@import 'USER_INPUT'">content</div>

6. Multiple properties:
   <div style="color: red; USER_INPUT: value">content</div>
"""

REMEDIATION = """
1. Sanitize all user input before using in style attributes
2. Block expression() function
3. Validate CSS property names and values
4. Use Content Security Policy (CSP) with style-src
5. Escape CSS special characters
6. Block javascript: protocol in CSS
7. Audit all style attribute usage for user input
8. Use framework-safe CSS handling
"""

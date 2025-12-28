#!/usr/bin/env python3

"""
Project: BRS-KB (BRS XSS Knowledge Base)
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: 2025-12-27 UTC
Status: Created
Telegram: https://t.me/EasyProTech

CSS Anchor Positioning Context - Data Module
"""

DESCRIPTION = """
CSS Anchor Positioning allows positioning elements relative to anchor elements.
The API can be exploited for XSS if user input is injected into anchor positioning
CSS properties or anchor names, allowing execution of scripts via CSS injection.

Vulnerability occurs when:
- User-controlled data is injected into anchor-name property
- Anchor positioning values contain user input
- CSS position-anchor uses user input
- Anchor element IDs are user-controlled

Common injection points:
- anchor-name CSS property
- position-anchor CSS property
- anchor() function values
- Anchor element id attributes
"""

ATTACK_VECTOR = """
1. Anchor name injection:
   .element {
       anchor-name: USER_INPUT;
   }

2. Position anchor injection:
   .element {
       position-anchor: USER_INPUT;
   }

3. Anchor function injection:
   .element {
       top: anchor(USER_INPUT);
   }

4. ID injection in anchor:
   <div id="USER_INPUT"></div>

5. CSS expression injection:
   .element {
       anchor-name: expression(USER_INPUT);
   }
"""

REMEDIATION = """
1. Sanitize all user input before using in CSS
2. Validate anchor names against allowlist
3. Escape CSS special characters
4. Use Content Security Policy (CSP) with style-src
5. Validate anchor element IDs
6. Avoid user input in CSS properties
7. Use CSS custom properties safely
8. Audit all anchor positioning code for user input
"""

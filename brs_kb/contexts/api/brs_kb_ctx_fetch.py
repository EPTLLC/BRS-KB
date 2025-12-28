#!/usr/bin/env python3
# Project: BRS-KB
# Company: EasyProTech LLC (www.easypro.tech)
# Dev: Brabus
# Date: 2025-12-27 UTC
# Status: Refactored
# Telegram: https://t.me/EasyProTech

"""
Fetch API XSS Context

XSS through Fetch API manipulation, response handling, and CORS abuse.
"""

DETAILS = {
    "title": "Fetch API XSS",
    "severity": "medium",
    "cvss_score": 6.5,
    "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:N/A:N",
    "reliability": "high",
    "cwe": ["CWE-79", "CWE-352"],
    "owasp": ["A03:2021"],
    "tags": ["fetch", "api", "cors", "xss", "javascript"],
    "description": """
Fetch API XSS occurs when attacker can control fetch URLs, manipulate
response handling, or exploit CORS misconfigurations. Response data
injected into DOM without sanitization leads to XSS.
""",
    "attack_vector": """
FETCH API XSS VECTORS:

1. URL PARAMETER INJECTION
   fetch(userUrl)
   With malicious endpoint

2. RESPONSE.TEXT() TO INNERHTML
   fetch(url).then(r => r.text())
     .then(html => el.innerHTML = html)

3. RESPONSE.JSON() INJECTION
   fetch(url).then(r => r.json())
     .then(data => el.innerHTML = data.html)

4. CORS HEADER MANIPULATION
   Access-Control-Allow-Origin: *
   Allows cross-origin data theft

5. REDIRECT EXPLOITATION
   fetch() follows redirects
   To attacker-controlled URL

6. TIMING ATTACKS
   performance.now() with fetch
   Cross-origin timing leaks

7. ABORTCONTROLLER ABUSE
   Resource exhaustion attacks

8. READABLESTREAM INJECTION
   Stream data into DOM

9. CREDENTIALS MODE
   credentials: 'include'
   CSRF via fetch
""",
    "remediation": """
FETCH API XSS PREVENTION:

1. VALIDATE URLS
   const url = new URL(userInput)
   Check origin before fetch

2. SANITIZE RESPONSES
   fetch(url).then(r => r.text())
     .then(html => el.innerHTML = DOMPurify.sanitize(html))

3. USE TEXTCONTENT
   el.textContent = data
   Not: el.innerHTML = data

4. PROPER CORS
   Access-Control-Allow-Origin: specific-origin
   Not: *

5. VALIDATE CONTENT-TYPE
   Check response Content-Type header
   Before parsing

6. NO REDIRECT
   fetch(url, { redirect: 'error' })
   Or validate redirect target

7. SAME-ORIGIN ONLY
   Check URL origin matches

8. IMPLEMENT CSP
   Block inline scripts
""",
}

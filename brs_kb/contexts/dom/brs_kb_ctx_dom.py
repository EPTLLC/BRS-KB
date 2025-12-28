#!/usr/bin/env python3
# Project: BRS-KB
# Company: EasyProTech LLC (www.easypro.tech)
# Dev: Brabus
# Date: 2025-12-27 UTC
# Status: Refactored
# Telegram: https://t.me/EasyProTech

"""
DOM Context XSS

Generic DOM manipulation context for DOM-based XSS attacks through
various DOM APIs and sink functions.
"""

DETAILS = {
    "title": "DOM Context XSS",
    "severity": "high",
    "cvss_score": 7.4,
    "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
    "reliability": "high",
    "cwe": ["CWE-79"],
    "owasp": ["A03:2021"],
    "tags": ["dom", "xss", "client-side", "javascript", "sink"],
    "description": """
DOM Context XSS occurs when user input flows into DOM manipulation APIs
without proper sanitization. Unlike reflected/stored XSS, the payload never
reaches the server - it executes entirely client-side through DOM APIs.

Key characteristics:
- Server logs may not contain the payload
- Client-side sanitization is critical
- Often involves dangerous sink functions
- Hard to detect with server-side scanning
""",
    "attack_vector": """
DOM XSS SINK FUNCTIONS:

1. DOCUMENT.WRITE
   document.write('<script>alert(1)</script>')

2. INNERHTML
   element.innerHTML = '<img src=x onerror=alert(1)>'

3. OUTERHTML
   element.outerHTML = '<img src=x onerror=alert(1)>'

4. INSERTADJACENTHTML
   el.insertAdjacentHTML('beforeend', payload)

5. DOCUMENT.WRITELN
   document.writeln(payload)

6. CREATECONTEXTUALFRAGMENT
   range.createContextualFragment(payload)

7. DOMPARSER
   new DOMParser().parseFromString(payload, 'text/html')

8. APPENDCHILD WITH SCRIPT
   script = document.createElement('script')
   script.textContent = payload

9. JQUERY METHODS
   $(selector).html(payload)
   $(selector).append(payload)
   $(payload).appendTo(target)

10. EVAL-LIKE SINKS
    eval(), setTimeout(), setInterval()
    new Function(), script.src
""",
    "remediation": """
DOM XSS PREVENTION:

1. USE TEXTCONTENT
   element.textContent = userInput
   Never: element.innerHTML = userInput

2. SANITIZE WITH DOMPURIFY
   const clean = DOMPurify.sanitize(dirty)
   element.innerHTML = clean

3. AVOID DOCUMENT.WRITE
   Completely deprecated pattern
   Use createElement + appendChild

4. USE CREATEELEMENT PATTERN
   const el = document.createElement('div')
   el.textContent = userInput
   parent.appendChild(el)

5. IMPLEMENT TRUSTED TYPES
   Content-Security-Policy: require-trusted-types-for 'script'

6. VALIDATE SOURCES
   Sanitize: location.hash, location.search
   Validate: postMessage data
   Check: document.referrer

7. CSP FOR DOM XSS
   script-src 'strict-dynamic'
   Prevents inline script execution
""",
}

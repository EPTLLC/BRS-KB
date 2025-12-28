#!/usr/bin/env python3
# Project: BRS-KB
# Company: EasyProTech LLC (www.easypro.tech)
# Dev: Brabus
# Date: 2025-12-27 UTC
# Status: Refactored
# Telegram: https://t.me/EasyProTech

"""
PDF XSS Context

XSS through PDF files and PDF viewers/plugins.
"""

DETAILS = {
    "title": "Cross-Site Scripting (XSS) in PDF Documents",
    "severity": "medium",
    "cvss_score": 6.1,
    "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:N/A:N",
    "reliability": "medium",
    "cwe": ["CWE-79"],
    "owasp": ["A03:2021"],
    "tags": ["pdf", "javascript", "pdfjs", "file-upload", "xss"],
    "description": """
PDF XSS exploits JavaScript execution in PDF files when opened in browser
plugins or PDF viewers. PDFs can contain embedded JavaScript, form actions,
and URI handlers that execute when the PDF is opened or interacted with.
""",
    "attack_vector": """
PDF XSS VECTORS:

1. APP.ALERT()
   PDF JavaScript: app.alert('XSS')

2. SUBMITFORM() JAVASCRIPT URI
   this.submitForm('javascript:alert(1)')

3. EMBEDDED JAVASCRIPT
   /OpenAction /JavaScript

4. OPENACTION LAUNCH
   /OpenAction << /S /JavaScript /JS (app.alert(1)) >>

5. PDF FORM SUBMISSION
   Form action to javascript: URL

6. ANNOTATION JAVASCRIPT
   Link annotation with JavaScript action

7. NAMED ACTION TRIGGERS
   /Named /GoTo with script execution

8. LINK ANNOTATIONS
   /A << /S /URI /URI (javascript:alert(1)) >>

9. EMBEDDED FLASH (LEGACY)
   Flash object in PDF

10. PDF.JS VULNERABILITIES
    XSS in Mozilla's PDF.js library
""",
    "remediation": """
PDF XSS PREVENTION:

1. DISABLE PDF JAVASCRIPT
   Configure viewers to block JavaScript

2. SANDBOXED VIEWING
   Open PDFs in isolated iframe
   sandbox="allow-same-origin"

3. STRIP JAVASCRIPT
   Process uploaded PDFs to remove scripts
   Use libraries like pdf-lib

4. CONTENT-DISPOSITION
   Content-Disposition: attachment
   Forces download instead of inline view

5. PDF.JS WITH CSP
   Content-Security-Policy: script-src 'self'
   Block inline scripts in PDF.js

6. VALIDATE PDF STRUCTURE
   Check for /JavaScript, /OpenAction
   Reject suspicious PDFs

7. SEPARATE DOMAIN
   Serve PDFs from sandbox domain
""",
}

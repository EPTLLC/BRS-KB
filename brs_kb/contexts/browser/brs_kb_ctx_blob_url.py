#!/usr/bin/env python3
# Project: BRS-KB
# Company: EasyProTech LLC (www.easypro.tech)
# Dev: Brabus
# Date: 2025-12-27 UTC
# Status: Refactored
# Telegram: https://t.me/EasyProTech

"""
Blob URL XSS Context

XSS through Blob URLs, Object URLs, and dynamic script/resource creation.
"""

DETAILS = {
    "title": "Blob URL XSS",
    "severity": "high",
    "cvss_score": 7.3,
    "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
    "reliability": "high",
    "cwe": ["CWE-79"],
    "owasp": ["A03:2021"],
    "tags": ["blob", "url", "createobjecturl", "xss", "dynamic"],
    "description": """
Blob URL XSS exploits dynamic URL generation via URL.createObjectURL()
with attacker-controlled Blob content. The generated blob: URL can contain
malicious HTML/JS that executes when loaded in iframes, Workers, or scripts.
""",
    "attack_vector": """
BLOB URL XSS VECTORS:

1. BLOB HTML IN IFRAME
   const blob = new Blob([userHtml], {type: 'text/html'})
   iframe.src = URL.createObjectURL(blob)

2. BLOB JS FOR SCRIPT
   const blob = new Blob([userCode], {type: 'text/javascript'})
   script.src = URL.createObjectURL(blob)

3. BLOB WORKER
   const blob = new Blob([workerCode])
   new Worker(URL.createObjectURL(blob))

4. FILEREADER ABUSE
   reader.readAsText(userFile)
   el.innerHTML = reader.result

5. DYNAMIC RESOURCE
   URL.createObjectURL(userBlob)
   Load as image/audio/video

6. BLOB PDF
   PDF with embedded JavaScript

7. BLOB SVG
   SVG with script payloads

8. DATA URL
   data:text/html,<script>alert(1)</script>
""",
    "remediation": """
BLOB URL XSS PREVENTION:

1. SANITIZE BLOB CONTENT
   const clean = DOMPurify.sanitize(input)
   new Blob([clean], {type: 'text/html'})

2. VALIDATE MIME TYPES
   Only allow safe MIME types
   Block text/html, text/javascript

3. CSP BLOB RESTRICTION
   Content-Security-Policy: script-src 'self'
   Blocks blob: script execution

4. REVOKE AFTER USE
   const url = URL.createObjectURL(blob)
   // use url
   URL.revokeObjectURL(url)

5. BLOCK SCRIPT EXECUTION
   Sandbox iframes with blob content
   sandbox="allow-same-origin"

6. VALIDATE FILE INPUT
   Check file type before reading
   Sanitize FileReader results
""",
}

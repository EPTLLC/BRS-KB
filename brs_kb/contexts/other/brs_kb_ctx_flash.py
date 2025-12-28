#!/usr/bin/env python3
# Project: BRS-KB
# Company: EasyProTech LLC (www.easypro.tech)
# Dev: Brabus
# Date: 2025-12-27 UTC
# Status: Refactored
# Telegram: https://t.me/EasyProTech

"""
Flash XSS Context (Legacy)

XSS through Adobe Flash SWF files (deprecated but still relevant for legacy systems).
"""

DETAILS = {
    "title": "Flash XSS (Legacy)",
    "severity": "high",
    "cvss_score": 7.5,
    "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
    "reliability": "low",
    "cwe": ["CWE-79"],
    "owasp": ["A03:2021"],
    "tags": ["flash", "swf", "legacy", "actionscript", "xss"],
    "description": """
Flash XSS exploited ActionScript's ability to execute JavaScript via
ExternalInterface, getURL(), and navigateToURL(). While Flash is deprecated,
legacy systems and old SWF files may still be vulnerable. This context is
included for completeness and auditing legacy applications.
""",
    "attack_vector": """
FLASH XSS VECTORS (LEGACY):

1. EXTERNALINTERFACE.CALL()
   ExternalInterface.call("eval", "alert(1)")
   Calls JavaScript from ActionScript

2. GETURL() JAVASCRIPT
   getURL("javascript:alert(1)")
   Navigates to JavaScript URI

3. NAVIGATETOURL()
   navigateToURL(new URLRequest("javascript:alert(1)"))

4. FLASHVARS INJECTION
   <embed src="swf.swf" FlashVars="data=<script>alert(1)</script>">

5. LOCALCONNECTION
   Cross-SWF communication exploitation

6. CROSSDOMAIN.XML
   <cross-domain-policy><allow-access-from domain="*"/></cross-domain-policy>
   Allows any origin to read SWF data

7. SWF FILE UPLOAD
   Upload malicious SWF served from target domain

8. EMBEDDED FLASH
   <embed src="evil.swf"> in HTML

9. FLASH CSRF
   Cross-origin requests from ActionScript

10. EVAL-LIKE FUNCTIONS
    ActionScript dynamic code execution
""",
    "remediation": """
FLASH XSS PREVENTION:

1. REMOVE FLASH ENTIRELY
   Flash is end-of-life
   No security updates

2. UPGRADE TO HTML5
   Use Canvas, WebGL, WebAudio
   Modern video/animation APIs

3. IF UNAVOIDABLE
   Sanitize all FlashVars
   Validate parameters in ActionScript

4. RESTRICT CROSSDOMAIN.XML
   <cross-domain-policy>
     <allow-access-from domain="trusted.com"/>
   </cross-domain-policy>

5. ISOLATED DOMAIN
   Serve SWF from separate domain
   No cookies/auth on that domain
""",
}

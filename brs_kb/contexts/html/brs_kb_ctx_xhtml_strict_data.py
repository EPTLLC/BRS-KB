#!/usr/bin/env python3

"""
Project: BRS-KB (BRS XSS Knowledge Base)
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: 2025-12-27 UTC
Status: Created
Telegram: https://t.me/EasyProTech

XHTML Strict Mode Context - Data Module
"""

DESCRIPTION = """
XHTML strict mode enforces XML syntax rules.
Vulnerabilities occur when user input is injected into XHTML documents,
exploiting differences between HTML and XHTML parsing, allowing XSS attacks.

Vulnerability occurs when:
- User-controlled data is injected into XHTML content
- XML entities are user-controlled
- XHTML attributes contain user input
- CDATA sections include user input
- XML processing instructions use user input

Common injection points:
- XHTML element content
- XML entity references
- Attribute values
- CDATA sections
- Processing instructions
"""

ATTACK_VECTOR = """
1. Entity injection:
   <div>&USER_INPUT;</div>

2. CDATA injection:
   <![CDATA[USER_INPUT]]>

3. Attribute injection:
   <div id="USER_INPUT">content</div>

4. Processing instruction:
   <?USER_INPUT?>

5. Namespace injection:
   <div xmlns="http://www.w3.org/1999/xhtml">
       USER_INPUT
   </div>
"""

REMEDIATION = """
1. Sanitize all user input before using in XHTML
2. Validate XML entity references
3. Escape XML special characters
4. Use Content Security Policy (CSP)
5. Validate XHTML document structure
6. Audit all XHTML generation code for user input
7. Use XML parsers with strict validation
8. Disable entity expansion if possible
"""

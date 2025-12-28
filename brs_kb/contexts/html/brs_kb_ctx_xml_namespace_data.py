#!/usr/bin/env python3

"""
Project: BRS-KB (BRS XSS Knowledge Base)
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: 2025-12-27 UTC
Status: Created
Telegram: https://t.me/EasyProTech

XML Namespace Injection Context - Data Module
"""

DESCRIPTION = """
XML namespaces allow qualifying element and attribute names.
Vulnerabilities occur when user input is injected into XML namespace declarations,
allowing XSS attacks through namespace manipulation or namespace-relative XPath.

Vulnerability occurs when:
- User-controlled data is injected into xmlns attributes
- Namespace prefixes are user-controlled
- XML documents include user input in namespace declarations
- XPath expressions use user-controlled namespaces
- SVG/XML content includes namespace injection

Common injection points:
- xmlns attribute values
- xmlns:* namespace declarations
- Namespace prefixes
- XML document root namespace
- XPath namespace context
"""

ATTACK_VECTOR = """
1. xmlns injection:
   <div xmlns="USER_INPUT">content</div>

2. Namespace prefix injection:
   <div xmlns:prefix="USER_INPUT">content</div>

3. SVG namespace injection:
   <svg xmlns="USER_INPUT">
       <script>alert(1)</script>
   </svg>

4. XPath namespace injection:
   document.evaluate('//USER_INPUT:element', ...)

5. XML document injection:
   <?xml version="1.0" encoding="UTF-8"?>
   <root xmlns="USER_INPUT">content</root>
"""

REMEDIATION = """
1. Sanitize all user input before using in namespace declarations
2. Validate namespace URIs against allowlist
3. Escape XML special characters
4. Use Content Security Policy (CSP)
5. Validate XML document structure
6. Audit all XML/SVG generation code for user input
7. Use XML parsers with namespace validation
8. Whitelist allowed namespace URIs
"""

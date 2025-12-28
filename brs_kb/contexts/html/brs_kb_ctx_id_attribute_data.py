#!/usr/bin/env python3

"""
Project: BRS-KB (BRS XSS Knowledge Base)
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: 2025-12-27 UTC
Status: Created
Telegram: https://t.me/EasyProTech

ID Attribute Injection Context - Data Module
"""

DESCRIPTION = """
id attribute provides unique identifier for elements.
Vulnerabilities occur when user input is injected into id attributes,
allowing DOM manipulation, CSS injection, or JavaScript access issues.

Vulnerability occurs when:
- User-controlled data is injected into id attribute values
- ID values are used in CSS selectors
- getElementById() uses user input
- ID values affect JavaScript behavior
- CSS injection occurs through ID selectors

Common injection points:
- id attribute values
- getElementById() with user input
- CSS #id selectors
- jQuery #id selectors
- ID-based event handlers
"""

ATTACK_VECTOR = """
1. ID value injection:
   <div id="USER_INPUT">content</div>

2. getElementById injection:
   document.getElementById(USER_INPUT);

3. CSS selector injection:
   document.querySelector('#' + USER_INPUT);

4. jQuery selector injection:
   $('#' + USER_INPUT);

5. ID with special chars:
   <div id="id-USER_INPUT">content</div>

6. Multiple IDs (invalid but parsed):
   <div id="id1" id="USER_INPUT">content</div>
"""

REMEDIATION = """
1. Sanitize all user input before using in id attributes
2. Validate ID values against allowlist
3. Escape CSS special characters
4. Use Content Security Policy (CSP)
5. Validate CSS selector usage
6. Audit all id attribute usage for user input
7. Use framework-safe ID handling
8. Whitelist allowed ID patterns
"""

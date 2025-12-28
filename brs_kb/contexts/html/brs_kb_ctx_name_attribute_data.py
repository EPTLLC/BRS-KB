#!/usr/bin/env python3

"""
Project: BRS-KB (BRS XSS Knowledge Base)
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: 2025-12-27 UTC
Status: Created
Telegram: https://t.me/EasyProTech

name Attribute Injection Context - Data Module
"""

DESCRIPTION = """
name attribute identifies form elements and other elements.
Vulnerabilities occur when user input is injected into name attributes,
allowing form manipulation, DOM access, or JavaScript reference issues.

Vulnerability occurs when:
- User-controlled data is injected into name attribute values
- Form element names are user-controlled
- getElementsByName() uses user input
- Form submission uses user-controlled names
- JavaScript references use name values

Common injection points:
- name attribute values
- Form input names
- getElementsByName() with user input
- Form data access
- Window object property access
"""

ATTACK_VECTOR = """
1. Name value injection:
   <input name="USER_INPUT" value="test">

2. getElementsByName injection:
   document.getElementsByName(USER_INPUT);

3. Form data injection:
   form[USER_INPUT].value = 'xss';

4. Window property injection:
   window[USER_INPUT] = value;

5. Form submission:
   <form>
       <input name="USER_INPUT" value="xss">
   </form>

6. Multiple names (invalid but parsed):
   <input name="name1" name="USER_INPUT">
"""

REMEDIATION = """
1. Sanitize all user input before using in name attributes
2. Validate name values against allowlist
3. Escape HTML entities in attribute values
4. Use Content Security Policy (CSP)
5. Validate form element names
6. Audit all name attribute usage for user input
7. Use framework-safe form handling
8. Whitelist allowed name patterns
"""

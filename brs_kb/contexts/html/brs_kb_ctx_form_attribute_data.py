#!/usr/bin/env python3

"""
Project: BRS-KB (BRS XSS Knowledge Base)
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: 2025-12-27 UTC
Status: Created
Telegram: https://t.me/EasyProTech

form Attribute Injection Context - Data Module
"""

DESCRIPTION = """
form attribute associates form elements with forms.
Vulnerabilities occur when user input is injected into form attributes,
allowing form manipulation, submission redirection, or DOM access issues.

Vulnerability occurs when:
- User-controlled data is injected into form attribute values
- Form IDs are user-controlled
- Form element association uses user input
- Form submission is manipulated
- Cross-form element association occurs

Common injection points:
- form attribute values
- Form element form attribute
- Form ID references
- Form submission handling
- getElementById() with form IDs
"""

ATTACK_VECTOR = """
1. Form attribute injection:
   <input form="USER_INPUT" name="field" value="test">

2. Form ID injection:
   <form id="USER_INPUT">
       <input name="field" value="test">
   </form>

3. Cross-form association:
   <form id="form1"></form>
   <input form="USER_INPUT" name="field">

4. Form submission:
   document.forms[USER_INPUT].submit();

5. Form element access:
   document.getElementById(USER_INPUT).elements;

6. Multiple form attributes (invalid):
   <input form="form1" form="USER_INPUT">
"""

REMEDIATION = """
1. Sanitize all user input before using in form attributes
2. Validate form IDs against allowlist
3. Escape HTML entities in attribute values
4. Use Content Security Policy (CSP)
5. Validate form element associations
6. Audit all form attribute usage for user input
7. Use framework-safe form handling
8. Whitelist allowed form ID patterns
"""

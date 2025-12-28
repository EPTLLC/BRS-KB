#!/usr/bin/env python3

"""
Project: BRS-KB (BRS XSS Knowledge Base)
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: 2025-12-27 UTC
Status: Created
Telegram: https://t.me/EasyProTech

data-* Attributes Context - Data Module
"""

DESCRIPTION = """
data-* attributes allow storing custom data on HTML elements.
Vulnerabilities occur when user input is injected into data-* attributes,
allowing XSS attacks through attribute manipulation or JavaScript access.

Vulnerability occurs when:
- User-controlled data is injected into data-* attribute values
- data-* attribute names are user-controlled
- JavaScript accesses data-* attributes with user input
- Attribute values are used in JavaScript without sanitization
- Dataset API uses unsanitized input

Common injection points:
- data-* attribute values
- data-* attribute names
- element.dataset property access
- getAttribute('data-*') usage
- jQuery .data() method
"""

ATTACK_VECTOR = """
1. data-* value injection:
   <div data-value="USER_INPUT">content</div>

2. data-* name injection:
   <div data-USER_INPUT="value">content</div>

3. Dataset access injection:
   element.dataset[USER_INPUT] = value;

4. getAttribute injection:
   element.getAttribute('data-' + USER_INPUT);

5. jQuery data injection:
   $('div').data(USER_INPUT, value);

6. Multiple data attributes:
   <div data-user="USER_INPUT" data-id="123">content</div>
"""

REMEDIATION = """
1. Sanitize all user input before using in data-* attributes
2. Validate data-* attribute names
3. Escape HTML entities in attribute values
4. Use Content Security Policy (CSP)
5. Validate dataset property access
6. Sanitize data when accessing via JavaScript
7. Audit all data-* attribute usage for user input
8. Use framework-safe attribute handling
"""

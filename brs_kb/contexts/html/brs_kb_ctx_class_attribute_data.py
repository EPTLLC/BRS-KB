#!/usr/bin/env python3

"""
Project: BRS-KB (BRS XSS Knowledge Base)
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: 2025-12-27 UTC
Status: Created
Telegram: https://t.me/EasyProTech

class Attribute Manipulation Context - Data Module
"""

DESCRIPTION = """
class attribute allows applying CSS classes to elements.
Vulnerabilities occur when user input is injected into class attributes,
allowing CSS injection attacks or manipulation of element styling.

Vulnerability occurs when:
- User-controlled data is injected into class attribute values
- Class names are user-controlled
- CSS selectors target user-controlled classes
- Class manipulation affects JavaScript behavior
- CSS injection occurs through class names

Common injection points:
- class attribute values
- Multiple class names
- Class name manipulation
- CSS selector injection
- JavaScript classList access
"""

ATTACK_VECTOR = """
1. Class value injection:
   <div class="USER_INPUT">content</div>

2. Multiple classes:
   <div class="existing-class USER_INPUT">content</div>

3. ClassList manipulation:
   element.classList.add(USER_INPUT);

4. CSS selector injection:
   document.querySelector('.' + USER_INPUT);

5. jQuery class injection:
   $('div').addClass(USER_INPUT);

6. Class name with special chars:
   <div class="class-USER_INPUT">content</div>
"""

REMEDIATION = """
1. Sanitize all user input before using in class attributes
2. Validate class names against allowlist
3. Escape CSS special characters
4. Use Content Security Policy (CSP) with style-src
5. Validate CSS selector usage
6. Audit all class attribute usage for user input
7. Use framework-safe class handling
8. Whitelist allowed class names
"""

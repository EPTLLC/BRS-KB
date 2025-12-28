#!/usr/bin/env python3

"""
Project: BRS-KB (BRS XSS Knowledge Base)
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: 2025-12-27 UTC
Status: Created
Telegram: https://t.me/EasyProTech

Trusted Types Bypass Context - Data Module
"""

DESCRIPTION = """
Trusted Types API provides runtime protection against DOM-based XSS.
However, various bypass techniques exist that can circumvent Trusted Types
protection, allowing XSS attacks even when Trusted Types is enabled.

Vulnerability occurs when:
- Trusted Types policies are misconfigured
- Bypass techniques exploit policy weaknesses
- Legacy APIs bypass Trusted Types checks
- Browser-specific behaviors circumvent protection
- Policy creation uses user input

Common bypass techniques:
- document.write() and writeln() bypasses
- innerHTML with trusted sinks
- createElement with user input
- setAttribute bypasses
- Legacy API exploitation
"""

ATTACK_VECTOR = """
1. document.write bypass:
   document.write(USER_INPUT)

2. createElement bypass:
   const el = document.createElement('script');
   el.textContent = USER_INPUT;
   document.body.appendChild(el);

3. setAttribute bypass:
   const el = document.createElement('div');
   el.setAttribute('onclick', USER_INPUT);

4. Legacy API bypass:
   document.body.insertAdjacentHTML('beforeend', USER_INPUT);

5. Policy bypass:
   const policy = trustedTypes.createPolicy('policy', {
       createHTML: (s) => s
   });
   document.body.innerHTML = policy.createHTML(USER_INPUT);
"""

REMEDIATION = """
1. Implement strict Trusted Types policies
2. Never allow user input in policy creation functions
3. Use default policy for all sinks
4. Audit all DOM manipulation code
5. Disable legacy APIs that bypass Trusted Types
6. Use Content Security Policy with require-trusted-types-for
7. Validate policy configurations
8. Test bypass techniques regularly
"""

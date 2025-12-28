#!/usr/bin/env python3

"""
Project: BRS-KB (BRS XSS Knowledge Base)
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: 2025-12-27 UTC
Status: Created
Telegram: https://t.me/EasyProTech

Web Locks API Context - Data Module
"""

DESCRIPTION = """
Web Locks API allows coordinating access to resources across browsing contexts.
The API can be exploited for XSS if user input is injected into lock names
or lock callback functions, allowing execution of arbitrary JavaScript.

Vulnerability occurs when:
- User-controlled data is used in lock names
- Lock callback functions contain user input
- Lock options are user-controlled
- Lock acquisition uses unsanitized input

Common injection points:
- navigator.locks.request() lock name parameter
- Lock callback function
- Lock options object
- Lock mode values
"""

ATTACK_VECTOR = """
1. Lock name injection:
   navigator.locks.request(USER_INPUT, () => {})

2. Callback injection:
   navigator.locks.request("lock", () => {
       USER_INPUT
   })

3. Eval in callback:
   navigator.locks.request("lock", () => {
       eval(USER_INPUT)
   })

4. DOM manipulation:
   navigator.locks.request("lock", () => {
       document.body.innerHTML = USER_INPUT;
   })

5. Script creation:
   navigator.locks.request("lock", () => {
       const s = document.createElement('script');
       s.textContent = USER_INPUT;
       document.body.appendChild(s);
   })
"""

REMEDIATION = """
1. Never use user input in lock names
2. Sanitize all data used in lock callbacks
3. Validate lock names against allowlist
4. Never pass user input to eval() in callbacks
5. Use Content Security Policy (CSP)
6. Validate lock options object
7. Sanitize DOM manipulation in callbacks
8. Audit all Web Locks API usage for user input
"""

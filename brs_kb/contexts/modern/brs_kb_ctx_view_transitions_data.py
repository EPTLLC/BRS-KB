#!/usr/bin/env python3

"""
Project: BRS-KB (BRS XSS Knowledge Base)
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: 2025-12-27 UTC
Status: Created
Telegram: https://t.me/EasyProTech

View Transitions API Context - Data Module
"""

DESCRIPTION = """
View Transitions API allows creating smooth transitions between pages or DOM states.
The API provides a callback mechanism that can be exploited for XSS if user input
is passed to the startViewTransition() callback function.

Vulnerability occurs when:
- User-controlled data is passed to document.startViewTransition(callback)
- Callback function executes user-controlled JavaScript
- DOM manipulation within callback uses unsanitized input
- Transition state includes injected content

Common injection points:
- Callback function parameters
- DOM manipulation within transition callback
- Transition state updates
- CSS transition properties
"""

ATTACK_VECTOR = """
1. Direct callback injection:
   document.startViewTransition(() => USER_INPUT)

2. DOM manipulation in callback:
   document.startViewTransition(() => {
       document.body.innerHTML = USER_INPUT;
   })

3. Eval in callback:
   document.startViewTransition(() => eval(USER_INPUT))

4. Location manipulation:
   document.startViewTransition(() => {
       location = USER_INPUT;
   })

5. Script creation:
   document.startViewTransition(() => {
       const s = document.createElement('script');
       s.textContent = USER_INPUT;
       document.body.appendChild(s);
   })
"""

REMEDIATION = """
1. Never pass user input directly to startViewTransition callback
2. Sanitize all user input before using in transition callbacks
3. Use Content Security Policy (CSP) to prevent inline script execution
4. Validate and escape all DOM manipulation within callbacks
5. Use Trusted Types API to prevent DOM-based XSS
6. Implement input validation and output encoding
7. Use framework-safe methods for DOM updates
8. Audit all transition callbacks for user input usage
"""

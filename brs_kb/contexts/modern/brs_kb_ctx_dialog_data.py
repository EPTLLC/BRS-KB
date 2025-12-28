#!/usr/bin/env python3

"""
Project: BRS-KB (BRS XSS Knowledge Base)
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: 2025-12-27 UTC
Status: Created
Telegram: https://t.me/EasyProTech

Dialog API Context - Data Module
"""

DESCRIPTION = """
Dialog API allows creating modal dialogs natively in HTML.
The API provides close and cancel events that can be exploited for XSS
if user input is injected into dialog content or event handlers.

Vulnerability occurs when:
- User-controlled data is injected into dialog content
- Event handlers (close, cancel) contain user input
- Dialog content includes unsanitized HTML
- Dialog methods (showModal, show, close) use user input

Common injection points:
- onclose event handler
- oncancel event handler
- Dialog content (innerHTML)
- Form method=dialog with user-controlled action
- Dialog backdrop click handlers
"""

ATTACK_VECTOR = """
1. Event handler injection:
   <dialog id=x onclose="USER_INPUT">
       <form method=dialog><button>Close</button></form>
   </dialog>

2. Content injection:
   <dialog id=x onclose=alert(1)>USER_INPUT</dialog>

3. Form action injection:
   <dialog id=x onclose=alert(1)>
       <form method=dialog action="USER_INPUT">
           <input type=submit>
       </form>
   </dialog>

4. Nested dialog:
   <dialog id=x onclose=alert(1)>
       <dialog id=y oncancel="USER_INPUT"></dialog>
   </dialog>

5. SVG in dialog:
   <dialog id=x onclose=alert(1)>
       <svg onload="USER_INPUT"></svg>
   </dialog>
"""

REMEDIATION = """
1. Sanitize all user input before injecting into dialog content
2. Never use user input in event handlers (close, cancel)
3. Use textContent instead of innerHTML for dialog content
4. Validate form action attributes in dialog forms
5. Implement Content Security Policy (CSP)
6. Use framework-safe methods for dialog manipulation
7. Escape all HTML entities in user-controlled content
8. Audit all dialog-related code for user input usage
"""

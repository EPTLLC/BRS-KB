#!/usr/bin/env python3

"""
Project: BRS-KB (BRS XSS Knowledge Base)
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: 2025-12-27 UTC
Status: Created
Telegram: https://t.me/EasyProTech

Popover API Context - Data Module
"""

DESCRIPTION = """
Popover API allows creating popover elements without JavaScript.
The API provides toggle and beforetoggle events that can be exploited for XSS
if user input is injected into popover content or event handlers.

Vulnerability occurs when:
- User-controlled data is injected into popover content
- Event handlers (toggle, beforetoggle) contain user input
- Popover content includes unsanitized HTML
- Popover attributes are controlled by user input

Common injection points:
- popover attribute values
- toggle event handlers
- beforetoggle event handlers
- Popover content (innerHTML)
- Popover showPopover/hidePopover/togglePopover method parameters
"""

ATTACK_VECTOR = """
1. Event handler injection:
   <div popover ontoggle="USER_INPUT">

2. Content injection:
   <div popover>USER_INPUT</div>

3. Method injection:
   <div id=x popover></div>
   <script>x.showPopover(); USER_INPUT</script>

4. Nested popover injection:
   <div popover>
       <div popover ontoggle="USER_INPUT"></div>
   </div>

5. SVG in popover:
   <div popover>
       <svg onload="USER_INPUT"></svg>
   </div>
"""

REMEDIATION = """
1. Sanitize all user input before injecting into popover content
2. Never use user input in event handlers (toggle, beforetoggle)
3. Use textContent instead of innerHTML for popover content
4. Implement Content Security Policy (CSP)
5. Validate popover attribute values
6. Use framework-safe methods for popover manipulation
7. Escape all HTML entities in user-controlled content
8. Audit all popover-related code for user input usage
"""

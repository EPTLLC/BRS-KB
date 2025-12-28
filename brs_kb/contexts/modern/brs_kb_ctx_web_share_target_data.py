#!/usr/bin/env python3

"""
Project: BRS-KB (BRS XSS Knowledge Base)
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: 2025-12-27 UTC
Status: Created
Telegram: https://t.me/EasyProTech

Web Share Target API Context - Data Module
"""

DESCRIPTION = """
Web Share Target API allows web apps to receive shared content.
The API can be exploited for XSS if user input from shared data is injected
into the page without sanitization, allowing execution of arbitrary JavaScript.

Vulnerability occurs when:
- Shared data (title, text, url) is injected into DOM without sanitization
- Shared files are processed without validation
- Share target handler uses unsanitized input
- Shared content is rendered as HTML

Common injection points:
- navigator.share() shared data
- Web Share Target manifest entry
- Share target handler URL parameters
- Shared file content processing
"""

ATTACK_VECTOR = """
1. Title injection:
   navigator.share({title: USER_INPUT})

2. Text injection:
   navigator.share({text: USER_INPUT})

3. URL injection:
   navigator.share({url: USER_INPUT})

4. DOM injection from shared data:
   // In share target handler:
   document.body.innerHTML = sharedData.text;

5. URL parameter injection:
   // share_target handler receives:
   ?title=USER_INPUT&text=USER_INPUT
"""

REMEDIATION = """
1. Sanitize all shared data before rendering
2. Use textContent instead of innerHTML for shared content
3. Validate shared URLs against allowlist
4. Sanitize shared file content
5. Implement Content Security Policy (CSP)
6. Validate share target manifest entries
7. Escape HTML entities in shared data
8. Audit all share target handlers for user input
"""

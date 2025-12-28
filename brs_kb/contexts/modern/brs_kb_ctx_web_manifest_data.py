#!/usr/bin/env python3

"""
Project: BRS-KB (BRS XSS Knowledge Base)
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: 2025-12-27 UTC
Status: Created
Telegram: https://t.me/EasyProTech

Web App Manifest Context - Data Module
"""

DESCRIPTION = """
Web App Manifest defines metadata for Progressive Web Apps.
The manifest JSON can be exploited for XSS if user input is injected into
manifest properties, allowing execution of scripts or navigation to malicious URLs.

Vulnerability occurs when:
- User-controlled data is injected into manifest JSON
- Manifest URLs (start_url, scope) are user-controlled
- Manifest icons contain user input
- Manifest shortcuts use user input
- Manifest share_target entries contain user input

Common injection points:
- start_url property
- scope property
- icons array URLs
- shortcuts array
- share_target entries
- theme_color, background_color values
"""

ATTACK_VECTOR = """
1. Start URL injection:
   {"start_url": "USER_INPUT"}

2. Scope injection:
   {"scope": "USER_INPUT"}

3. JavaScript protocol:
   {"start_url": "javascript:alert(1)"}

4. Data URL:
   {"start_url": "data:text/html,<script>alert(1)</script>"}

5. Icon URL injection:
   {"icons": [{"src": "USER_INPUT", "sizes": "192x192"}]}

6. Shortcut injection:
   {"shortcuts": [{"name": "USER_INPUT", "url": "/"}]}
"""

REMEDIATION = """
1. Never allow user input in manifest JSON
2. Validate all manifest URLs against allowlist
3. Block javascript: and data: protocols in URLs
4. Sanitize manifest JSON before serving
5. Use Content Security Policy (CSP)
6. Validate manifest structure
7. Whitelist allowed manifest properties
8. Audit all manifest generation code for user input
"""

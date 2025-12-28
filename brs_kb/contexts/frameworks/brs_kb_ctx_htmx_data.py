#!/usr/bin/env python3

"""
Project: BRS-KB (BRS XSS Knowledge Base)
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: 2025-12-27 UTC
Status: Created
Telegram: https://t.me/EasyProTech

HTMX Injection Context - Data Module
"""

DESCRIPTION = """
HTMX allows adding interactivity to HTML via attributes.
The framework can be exploited for XSS if user input is injected into HTMX
attributes or response content, allowing execution of arbitrary JavaScript.

Vulnerability occurs when:
- User-controlled data is injected into HTMX attributes
- HTMX responses contain unsanitized user input
- HTMX swap operations use user input
- HTMX event handlers contain user input
- HTMX target selectors are user-controlled

Common injection points:
- hx-get, hx-post, hx-put, hx-delete attributes
- hx-target attribute
- hx-swap attribute
- hx-trigger attribute
- hx-on* event handlers
- HTMX response content
"""

ATTACK_VECTOR = """
1. URL injection:
   <div hx-get="USER_INPUT">Click</div>

2. JavaScript protocol:
   <div hx-get="javascript:alert(1)">Click</div>

3. Event handler injection:
   <div hx-on::click="USER_INPUT">Click</div>

4. Target injection:
   <div hx-target="USER_INPUT">Click</div>

5. Response injection:
   // Server response:
   <div hx-swap="innerHTML">USER_INPUT</div>

6. Trigger injection:
   <div hx-trigger="USER_INPUT">Click</div>
"""

REMEDIATION = """
1. Sanitize all user input before using in HTMX attributes
2. Validate HTMX URLs against allowlist
3. Block javascript: protocol in HTMX URLs
4. Sanitize HTMX response content
5. Use Content Security Policy (CSP)
6. Validate HTMX target selectors
7. Escape HTML entities in user-controlled content
8. Audit all HTMX usage for user input
"""

#!/usr/bin/env python3

"""
Project: BRS-KB (BRS XSS Knowledge Base)
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: 2025-12-27 UTC
Status: Created
Telegram: https://t.me/EasyProTech

Blob URL Context - Data Module
"""

DESCRIPTION = """
Blob URLs allow creating URLs for Blob objects.
Vulnerabilities occur when user input is injected into Blob content or
Blob URL creation, allowing XSS attacks through malicious blob content.

Vulnerability occurs when:
- User-controlled data is injected into Blob content
- Blob URLs are created with user input
- Blob MIME types are user-controlled
- Blob content is executed as script
- Blob URLs bypass URL validation

Common injection points:
- Blob constructor content
- URL.createObjectURL() with user-controlled Blob
- Blob MIME type
- Blob content type
- Blob URL usage
"""

ATTACK_VECTOR = """
1. Blob content injection:
   const blob = new Blob([USER_INPUT], {type: 'text/html'});
   const url = URL.createObjectURL(blob);

2. JavaScript blob:
   const blob = new Blob(['alert(1)'], {type: 'application/javascript'});
   const url = URL.createObjectURL(blob);

3. SVG blob:
   const blob = new Blob(['<svg><script>alert(1)</script></svg>'],
                        {type: 'image/svg+xml'});
   const url = URL.createObjectURL(blob);

4. MIME type injection:
   const blob = new Blob(['content'], {type: USER_INPUT});

5. Blob URL injection:
   window.location = URL.createObjectURL(USER_INPUT);
"""

REMEDIATION = """
1. Never allow user input in Blob content
2. Validate Blob MIME types against allowlist
3. Block javascript MIME types
4. Use Content Security Policy (CSP)
5. Validate Blob URLs before use
6. Sanitize Blob content
7. Audit all Blob creation code for user input
8. Use framework-safe Blob handling
"""

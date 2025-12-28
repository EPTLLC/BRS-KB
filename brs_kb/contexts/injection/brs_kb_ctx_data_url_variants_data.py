#!/usr/bin/env python3

"""
Project: BRS-KB (BRS XSS Knowledge Base)
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: 2025-12-27 UTC
Status: Created
Telegram: https://t.me/EasyProTech

Data URL Variants Context - Data Module
"""

DESCRIPTION = """
Data URLs allow embedding data directly in URLs.
Various encoding and format variants can be exploited for XSS when user input
is injected into data URLs, allowing execution of arbitrary JavaScript.

Vulnerability occurs when:
- User-controlled data is injected into data URL content
- Data URL encoding is bypassed
- Base64 encoding is manipulated
- MIME types are user-controlled
- Data URL variants bypass filters

Common variants:
- data:text/html,<script>alert(1)</script>
- data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==
- data:text/html;charset=utf-8,<script>alert(1)</script>
- data:image/svg+xml,<svg><script>alert(1)</script></svg>
- data:application/javascript,alert(1)
"""

ATTACK_VECTOR = """
1. Basic data URL:
   data:text/html,USER_INPUT

2. Base64 encoded:
   data:text/html;base64,USER_INPUT

3. SVG data URL:
   data:image/svg+xml,USER_INPUT

4. JavaScript data URL:
   data:application/javascript,USER_INPUT

5. Charset variant:
   data:text/html;charset=utf-8,USER_INPUT

6. Double encoding:
   data%3Atext%2Fhtml%2CUSER_INPUT
"""

REMEDIATION = """
1. Never allow user input in data URLs
2. Block data: protocol in URL validation
3. Validate MIME types against allowlist
4. Use Content Security Policy (CSP)
5. Sanitize all URLs before use
6. Decode and validate data URL content
7. Audit all URL handling code for user input
8. Use framework-safe URL handling
"""

#!/usr/bin/env python3

"""
Project: BRS-KB (BRS XSS Knowledge Base)
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: 2025-12-27 UTC
Status: Created
Telegram: https://t.me/EasyProTech

@font-face Injection Context - Data Module
"""

DESCRIPTION = """
@font-face allows defining custom fonts.
Vulnerabilities occur when user input is injected into @font-face rules,
allowing XSS attacks through malicious font URLs or CSS injection.

Vulnerability occurs when:
- User-controlled data is injected into font URLs
- Font URLs point to malicious resources
- CSS injection occurs through @font-face
- Font data is user-controlled
- src property uses javascript: protocol

Common injection points:
- @font-face src URLs
- font-family property values
- font-display property
- unicode-range property
- Font file URLs
"""

ATTACK_VECTOR = """
1. URL injection:
   @font-face {
       font-family: 'Arial';
       src: url(USER_INPUT);
   }

2. JavaScript protocol:
   @font-face {
       src: url("javascript:alert(1)");
   }

3. Data URL:
   @font-face {
       src: url("data:text/css,body{background:url('javascript:alert(1)')}");
   }

4. External font:
   @font-face {
       src: url("https://evil.com/font.woff");
   }

5. Font-family injection:
   @font-face {
       font-family: USER_INPUT;
   }
"""

REMEDIATION = """
1. Never allow user input in @font-face URLs
2. Whitelist allowed font sources
3. Block javascript: and data: protocols
4. Validate font URLs against allowlist
5. Use Content Security Policy (CSP) with font-src
6. Sanitize CSS before parsing
7. Audit all CSS generation code for user input
8. Use framework-safe CSS handling
"""

#!/usr/bin/env python3

"""
Project: BRS-KB (BRS XSS Knowledge Base)
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: 2025-12-27 UTC
Status: Created
Telegram: https://t.me/EasyProTech

CSS @import Injection Context - Data Module
"""

DESCRIPTION = """
CSS @import allows importing external stylesheets.
Vulnerabilities occur when user input is injected into @import rules,
allowing XSS attacks through malicious stylesheet loading or CSS injection.

Vulnerability occurs when:
- User-controlled data is injected into @import URLs
- @import URLs point to malicious resources
- CSS injection occurs through @import
- Stylesheet content is user-controlled
- @import uses javascript: protocol

Common injection points:
- @import URL values
- @import url() function
- Stylesheet href attributes
- Link rel="stylesheet" href
- Style tag @import rules
"""

ATTACK_VECTOR = """
1. URL injection:
   @import "USER_INPUT";

2. JavaScript protocol:
   @import "javascript:alert(1)";

3. Data URL:
   @import "data:text/css,body{background:url('javascript:alert(1)')}";

4. External stylesheet:
   @import url("https://evil.com/xss.css");

5. Link tag injection:
   <link rel="stylesheet" href="USER_INPUT">
"""

REMEDIATION = """
1. Never allow user input in @import URLs
2. Whitelist allowed stylesheet sources
3. Block javascript: and data: protocols
4. Validate @import URLs against allowlist
5. Use Content Security Policy (CSP) with style-src
6. Sanitize CSS before parsing
7. Audit all CSS generation code for user input
8. Use framework-safe CSS handling
"""

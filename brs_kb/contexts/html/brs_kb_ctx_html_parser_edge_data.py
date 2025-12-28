#!/usr/bin/env python3

"""
Project: BRS-KB (BRS XSS Knowledge Base)
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: 2025-12-27 UTC
Status: Created
Telegram: https://t.me/EasyProTech

HTML Parser Edge Cases Context - Data Module
"""

DESCRIPTION = """
HTML parser has various edge cases and quirks that can be exploited.
Vulnerabilities occur when user input exploits parser edge cases,
allowing XSS attacks through unexpected parsing behavior.

Vulnerability occurs when:
- User input exploits parser normalization
- Malformed HTML is parsed unexpectedly
- Parser error recovery creates vulnerabilities
- Tag name edge cases are exploited
- Attribute parsing quirks are used

Common edge cases:
- Tag name case sensitivity
- Unclosed tags
- Nested tags
- Comment parsing
- DOCTYPE manipulation
- Script tag variations
"""

ATTACK_VECTOR = """
1. Case variation:
   <ScRiPt>alert(1)</ScRiPt>

2. Unclosed tag:
   <div><script>alert(1)</div>

3. Nested tags:
   <div><div><script>alert(1)</script></div></div>

4. Comment injection:
   <!--<script>alert(1)</script>-->

5. DOCTYPE injection:
   <!DOCTYPE USER_INPUT>

6. Script tag variation:
   <script src="data:text/javascript,alert(1)"></script>
"""

REMEDIATION = """
1. Use strict HTML parsers
2. Normalize HTML before parsing
3. Validate tag structure
4. Use Content Security Policy (CSP)
5. Sanitize all user input
6. Audit parser behavior
7. Test edge cases regularly
8. Use framework-safe HTML parsing
"""

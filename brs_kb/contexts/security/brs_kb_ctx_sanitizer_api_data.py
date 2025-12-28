#!/usr/bin/env python3

"""
Project: BRS-KB (BRS XSS Knowledge Base)
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: 2025-12-27 UTC
Status: Created
Telegram: https://t.me/EasyProTech

Sanitizer API Bypass Context - Data Module
"""

DESCRIPTION = """
Sanitizer API provides built-in HTML sanitization to prevent XSS.
However, various bypass techniques exist that can circumvent sanitization,
allowing XSS attacks even when Sanitizer API is used.

Vulnerability occurs when:
- Sanitizer configuration is misconfigured
- Bypass techniques exploit sanitizer weaknesses
- Browser-specific behaviors circumvent sanitization
- Policy creation uses user input
- Sanitized content is processed incorrectly

Common bypass techniques:
- Configuration manipulation
- Element attribute bypasses
- Event handler injection
- SVG/XML namespace exploitation
- CSS injection in style attributes
"""

ATTACK_VECTOR = """
1. Configuration bypass:
   const sanitizer = new Sanitizer({
       allowElements: [USER_INPUT]
   });

2. Attribute bypass:
   <div USER_INPUT="value">content</div>

3. Event handler bypass:
   <div onclick="USER_INPUT">content</div>

4. SVG bypass:
   <svg><script>USER_INPUT</script></svg>

5. Style injection:
   <div style="USER_INPUT">content</div>

6. Namespace bypass:
   <div xmlns="http://www.w3.org/1999/xhtml">
       <script>USER_INPUT</script>
   </div>
"""

REMEDIATION = """
1. Use strict Sanitizer configurations
2. Never allow user input in configuration
3. Validate sanitized output
4. Use Content Security Policy as defense in depth
5. Audit all sanitization code
6. Test bypass techniques regularly
7. Keep sanitizer library updated
8. Use allowlist-based sanitization
"""

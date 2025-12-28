#!/usr/bin/env python3

"""
Project: BRS-KB (BRS XSS Knowledge Base)
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: 2025-12-27 UTC
Status: Created
Telegram: https://t.me/EasyProTech

file:// URL Context - Data Module
"""

DESCRIPTION = """
file:// URLs allow accessing local files.
Vulnerabilities occur when user input is injected into file:// URLs,
allowing access to local files or XSS attacks through file content.

Vulnerability occurs when:
- User-controlled data is injected into file:// URLs
- File paths are user-controlled
- File content is executed as script
- Local file access bypasses security
- File URLs bypass URL validation

Common injection points:
- file:// URL construction
- File path manipulation
- Directory traversal in file paths
- File content execution
- Local file references
"""

ATTACK_VECTOR = """
1. File path injection:
   file://USER_INPUT

2. Directory traversal:
   file:///etc/passwd

3. Local HTML file:
   file:///path/to/file.html

4. JavaScript file:
   <script src="file:///path/to/script.js"></script>

5. Path manipulation:
   file:///../../etc/passwd
"""

REMEDIATION = """
1. Never allow user input in file:// URLs
2. Block file:// protocol in URL validation
3. Validate file paths against allowlist
4. Use Content Security Policy (CSP)
5. Sanitize all URLs before use
6. Restrict local file access
7. Audit all URL handling code for user input
8. Use framework-safe URL handling
"""

#!/usr/bin/env python3

"""
Project: BRS-KB (BRS XSS Knowledge Base)
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: 2025-12-27 UTC
Status: Created
Telegram: https://t.me/EasyProTech

Cross-Origin-Isolated Context - Data Module
"""

DESCRIPTION = """
Cross-Origin-Isolated contexts enable powerful APIs like SharedArrayBuffer.
These contexts have strict security requirements, but vulnerabilities can occur
when user input interacts with cross-origin isolated features or when isolation
is bypassed, allowing XSS attacks.

Vulnerability occurs when:
- Cross-origin isolation headers are misconfigured
- User input interacts with isolated APIs unsafely
- Isolation bypass techniques are exploited
- SharedArrayBuffer is used with user input
- Cross-origin communication is user-controlled

Common injection points:
- Cross-Origin-Embedder-Policy headers
- Cross-Origin-Opener-Policy headers
- SharedArrayBuffer manipulation
- postMessage in isolated contexts
- Worker creation in isolated contexts
"""

ATTACK_VECTOR = """
1. Header manipulation:
   Cross-Origin-Embedder-Policy: USER_INPUT

2. SharedArrayBuffer injection:
   const buffer = new SharedArrayBuffer(USER_INPUT);

3. postMessage injection:
   window.postMessage(USER_INPUT, '*');

4. Worker creation:
   new Worker(USER_INPUT, {type: 'module'});

5. Isolation bypass:
   // Misconfigured headers allow bypass
   window.opener.postMessage(USER_INPUT, '*');
"""

REMEDIATION = """
1. Properly configure Cross-Origin-Embedder-Policy
2. Properly configure Cross-Origin-Opener-Policy
3. Sanitize all user input for isolated APIs
4. Validate SharedArrayBuffer usage
5. Audit all cross-origin communication
6. Use Content Security Policy
7. Test isolation configuration
8. Monitor security headers
"""

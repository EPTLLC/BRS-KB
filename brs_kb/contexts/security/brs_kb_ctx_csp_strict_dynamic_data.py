#!/usr/bin/env python3

"""
Project: BRS-KB (BRS XSS Knowledge Base)
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: 2025-12-27 UTC
Status: Created
Telegram: https://t.me/EasyProTech

CSP strict-dynamic Bypass Context - Data Module
"""

DESCRIPTION = """
Content Security Policy strict-dynamic allows scripts loaded by trusted scripts.
This can be exploited if untrusted scripts gain trust through various techniques,
allowing execution of arbitrary JavaScript despite CSP protection.

Vulnerability occurs when:
- Scripts are dynamically created with user input
- Nonce values are predictable or leaked
- Script sources are user-controlled
- Trusted scripts load untrusted content
- Base tag manipulation affects script loading

Common bypass techniques:
- Nonce prediction or leakage
- Base tag injection
- Script source manipulation
- Dynamic script creation
- Trust chain exploitation
"""

ATTACK_VECTOR = """
1. Nonce leakage:
   <script nonce="LEAKED_NONCE">USER_INPUT</script>

2. Base tag injection:
   <base href="USER_INPUT">
   <script src="/script.js"></script>

3. Dynamic script creation:
   const s = document.createElement('script');
   s.src = USER_INPUT;
   document.head.appendChild(s);

4. Trusted script injection:
   <script nonce="TRUSTED">
       const s = document.createElement('script');
       s.textContent = USER_INPUT;
       document.head.appendChild(s);
   </script>

5. Import map manipulation:
   <script type="importmap" nonce="TRUSTED">
   {"imports":{"x":"USER_INPUT"}}
   </script>
"""

REMEDIATION = """
1. Use cryptographically secure nonces
2. Never leak nonce values to untrusted sources
3. Validate all script sources
4. Avoid user input in script creation
5. Implement strict CSP without unsafe-inline
6. Audit all dynamic script loading
7. Use Trusted Types with CSP
8. Test CSP bypass techniques regularly
"""

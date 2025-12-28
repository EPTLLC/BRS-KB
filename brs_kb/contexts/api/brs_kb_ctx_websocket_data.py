#!/usr/bin/env python3

"""
Project: BRS-KB (BRS XSS Knowledge Base)
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: 2025-12-04 19:21:27 UTC
Status: Created
Telegram: https://t.me/easyprotech

Cross-Site Scripting (XSS) in WebSocket Context Context - Data Module
Contains description and remediation data
"""

DESCRIPTION = """
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
"""

REMEDIATION = r"""
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

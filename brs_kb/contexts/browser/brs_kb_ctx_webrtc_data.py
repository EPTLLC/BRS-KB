#!/usr/bin/env python3

"""
Project: BRS-KB (BRS XSS Knowledge Base)
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: 2025-12-04 19:21:27 UTC
Status: Created
Telegram: https://t.me/easyprotech

WebRTC XSS Context - Data Module
Contains description and remediation data
"""

DESCRIPTION = """
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
"""

REMEDIATION = """
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
       .replace(/<script\b[^<]*(?:(?!<\\/script>)<[^<]*)*<\\/script>/gi, '')
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
"""

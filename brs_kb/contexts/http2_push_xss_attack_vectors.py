#!/usr/bin/env python3

"""
Project: BRS-KB (BRS XSS Knowledge Base)
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: 2025-12-04 19:21:27 UTC
Status: Created
Telegram: https://t.me/easyprotech

HTTP/2 Push XSS Context - Attack Vectors Module
"""

ATTACK_VECTOR = """
HTTP/2 PUSH XSS ATTACK VECTORS:

1. PUSH PATH INJECTION:
   Server push with user-controlled paths:
   server.push('/api/user/' + USER_INPUT);  // Path injection

   Attack payload:
   <script>alert(1)</script>

   Result: Server pushes /api/user/<script>alert(1)</script>

2. PUSH CONTENT INJECTION:
   Pushed resource content:
   const pushContent = '<!DOCTYPE html><html><body>' +
                       '<h1>Welcome, ' + USER_INPUT + '</h1>' +  // Content injection
                       '</body></html>';

   server.push('/welcome.html', pushContent);

3. PUSH HEADER INJECTION:
   HTTP/2 push headers:
   server.push('/user.css', cssContent, {
     'content-type': 'text/css',
     'x-user-name': USER_INPUT  // Header injection
   });

4. PUSH PROMISE INJECTION:
   Promise path injection:
   const promisePath = '/user/' + USER_INPUT + '/profile';  // Promise injection
   server.push(promisePath);

5. PUSH RESOURCE GENERATION:
   Dynamic resource generation:
   const resourcePath = '/generated/' + USER_INPUT + '.js';  // Resource path XSS
   const resourceContent = 'console.log("' + USER_INPUT + '");';  // Content XSS

   server.push(resourcePath, resourceContent);

ADVANCED HTTP/2 PUSH XSS TECHNIQUES:

6. PUSH DEPENDENCY INJECTION:
   Push dependency chains with XSS:
   server.push('/main.js', mainScript);
   server.push('/user-data.js', 'var userData = "' + USER_INPUT + '";');  // Dependency XSS

7. PUSH CACHE INJECTION:
   Cache manipulation with XSS:
   const cacheKey = 'user_' + USER_INPUT;  // Cache key injection
   const cachedContent = generateContent(USER_INPUT);  // Content injection

   server.push('/cached/' + cacheKey + '.html', cachedContent);

8. PUSH STREAM PRIORITY INJECTION:
   Stream priority with XSS:
   server.push('/priority-high.js', highPriorityScript, {
     priority: USER_INPUT  // Priority injection
   });

9. PUSH SETTINGS INJECTION:
   HTTP/2 settings frame manipulation:
   const maliciousSettings = {
     SETTINGS_HEADER_TABLE_SIZE: 4096,
     SETTINGS_ENABLE_PUSH: 1,
     SETTINGS_MAX_CONCURRENT_STREAMS: USER_INPUT  // Settings XSS
   };

10. PUSH CONTINUATION FRAME INJECTION:
    HTTP/2 continuation frames with XSS:
    const continuationData = USER_INPUT;  // Continuation injection
    server.push('/continuation.js', continuationData);

11. PUSH RESET FRAME ATTACK:
    Reset frames with malicious data:
    const resetReason = USER_INPUT;  // Reset reason XSS
    server.resetStream(streamId, resetReason);

12. PUSH WINDOW UPDATE INJECTION:
    Window update with XSS:
    const windowSize = parseInt(USER_INPUT);  // Window size injection
    server.updateWindow(windowSize);

13. PUSH PRIORITY FRAME INJECTION:
    Priority frame manipulation:
    const priorityData = {
      streamId: 1,
      weight: 256,
      dependency: USER_INPUT  // Dependency injection
    };

14. PUSH GOAWAY FRAME ATTACK:
    GoAway frames with XSS:
    const goAwayData = {
      lastStreamId: 0,
      errorCode: 0,
      debugData: USER_INPUT  // Debug data XSS
    };

15. PUSH ALTSVC FRAME INJECTION:
    Alternative service injection:
    const altSvcData = 'h2=":443"; ' + USER_INPUT;  // Alt-Svc XSS

HTTP/2 PUSH-SPECIFIC BYPASSES:

16. PUSH PROMISE PAD LENGTH ATTACK:
    Padding manipulation:
    const paddedPath = '/user/' + USER_INPUT + '/' + 'x'.repeat(255);  // Pad length XSS

17. PUSH SETTINGS ACK INJECTION:
    Settings acknowledgment with XSS:
    const settingsAck = USER_INPUT;  // Settings ack XSS

18. PUSH PRIORITY EXCLUSIVE INJECTION:
    Priority exclusive flag with XSS:
    const exclusivePriority = {
      streamId: USER_INPUT,  // Exclusive injection
      weight: 128,
      exclusive: true
    };

19. PUSH WINDOW SIZE INCREMENT ATTACK:
    Window size manipulation:
    const windowIncrement = USER_INPUT;  // Window increment XSS

20. PUSH HEADERS COMPRESSION ATTACK:
    HPACK compression with XSS:
    const compressedHeaders = hpack.encode({
      ':path': '/user/' + USER_INPUT,  // Compressed path XSS
      ':method': 'GET'
    });

REAL-WORLD ATTACK SCENARIOS:

21. RESOURCE PRELOADING ATTACK:
    - Server preloads user-specific resources
    - Resource path: /user/<script>alert(1)</script>/data.js
    - Pushed to all users
    - Global XSS execution

22. CACHING LAYER ATTACK:
    - CDN with HTTP/2 push
    - Push path: /api/user/<script>alert(1)</script>
    - Cached malicious content
    - Served to all CDN users

23. PERSONALIZATION ENGINE:
    - Personalized content delivery
    - Push content: Welcome <script>alert(1)</script>!
    - Pushed to user browsers
    - Personalized XSS attacks

24. API RESPONSE OPTIMIZATION:
    - API with push optimization
    - Push related data: /user/<script>alert(1)</script>/profile
    - API response includes XSS
    - Affects API consumers

25. TEMPLATE PUSHING:
    - Server-side template rendering
    - Push template: /template/<script>alert(1)</script>.html
    - Template served to users
    - Template-based XSS

26. STATIC ASSET PUSHING:
    - Static asset optimization
    - Push asset: /assets/<script>alert(1)</script>.css
    - CSS with XSS payload
    - Style-based attacks

27. LOCALIZATION PUSHING:
    - Multi-language content
    - Push locale: /locale/<script>alert(1)</script>.json
    - Localized XSS attacks
    - Language-specific attacks

HTTP/2 PUSH XSS DETECTION:

28. MANUAL TESTING:
    - Browser DevTools Network inspection
    - HTTP/2 push monitoring
    - Server push analysis
    - Resource content inspection

29. AUTOMATED SCANNING:
    - HTTP/2 push analysis
    - Push promise validation
    - Pushed content security testing
    - Cache poisoning detection

30. PROXY MONITORING:
    - HTTP/2 traffic interception
    - Push promise monitoring
    - Content validation
    - Compression analysis
"""

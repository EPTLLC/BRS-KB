#!/usr/bin/env python3

"""
Project: BRS-KB (BRS XSS Knowledge Base)
Company: EasyProTech LLC (www.easyprotech)
Dev: Brabus
Date: Sat 25 Oct 2025 12:00:00 UTC
Status: Created
Telegram: https://t.me/easyprotech

Knowledge Base: HTTP/2 Push XSS Context - Comprehensive Guide
"""

DETAILS = {
    "title": "Cross-Site Scripting (XSS) in HTTP/2 Push Context",
    # Metadata for SIEM/Triage Integration
    "severity": "medium",
    "cvss_score": 6.8,
    "cvss_vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:N",
    "reliability": "certain",
    "cwe": ["CWE-79"],
    "owasp": ["A03:2021"],
    "tags": ["xss", "http2", "server-push", "resource-injection", "modern-web"],
    "description": """
HTTP/2 Push XSS occurs when user input is reflected into HTTP/2 Server Push resources or when
push promises contain malicious content. HTTP/2 Server Push allows servers to proactively send
resources to clients before they are requested, improving performance. However, when push promises
or pushed content contain user-controlled data without sanitization, it can lead to XSS attacks
through pushed resources.

VULNERABILITY CONTEXT:
HTTP/2 Push XSS typically happens when:
1. Push promise paths contain user input
2. Pushed content includes user-generated data
3. Push resource URLs are dynamically generated
4. Push headers contain reflected content
5. Push content is cached and later served
6. Push resources are generated from templates

Common in:
- HTTP/2 enabled web servers
- CDN configurations with push
- Performance optimization systems
- Caching layers
- Template-based applications
- Resource bundling systems
- API response optimization

SEVERITY: MEDIUM
HTTP/2 Push XSS requires specific server configuration and user interaction. However, successful
exploitation can lead to persistent attacks through cached resources and affect multiple users
through server-initiated content delivery.
""",
    "attack_vector": """
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
""",
    "remediation": """
HTTP/2 PUSH XSS DEFENSE STRATEGY:

1. PUSH PATH VALIDATION (PRIMARY DEFENSE):
   Validate all push promise paths:

   function validatePushPath(path) {
     // Path must start with allowed prefix
     const allowedPrefixes = ['/api/', '/assets/', '/static/', '/public/'];
     if (!allowedPrefixes.some(prefix => path.startsWith(prefix))) {
       throw new Error('Invalid push path');
     }

     // Validate path format
     const pathPattern = /^\/[a-zA-Z0-9\/_-]+$/;
     if (!pathPattern.test(path)) {
       throw new Error('Invalid path format');
     }

     // Check for XSS patterns
     const dangerousPatterns = [
       /<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>/gi,
       /javascript:/gi,
       /vbscript:/gi,
       /on\w+\s*=/gi,
       /<[^>]*>/g
     ];

     for (const pattern of dangerousPatterns) {
       if (pattern.test(path)) {
         throw new Error('Malicious content in path');
       }
     }

     return path;
   }

2. PUSH CONTENT SANITIZATION:
   Sanitize all pushed content:

   function sanitizePushContent(content, contentType) {
     switch (contentType) {
       case 'text/html':
         return DOMPurify.sanitize(content);
       case 'application/javascript':
         return sanitizeJavaScript(content);
       case 'text/css':
         return sanitizeCSS(content);
       case 'application/json':
         return sanitizeJSON(content);
       default:
         return content;
     }
   }

3. SERVER PUSH RESTRICTIONS:
   Restrict server push functionality:

   // Only allow push for specific resource types
   const ALLOWED_PUSH_TYPES = ['text/css', 'application/javascript', 'image/*'];

   function canPushResource(resourcePath, contentType) {
     return ALLOWED_PUSH_TYPES.some(type => {
       if (type.endsWith('/*')) {
         return contentType.startsWith(type.slice(0, -1));
       }
       return contentType === type;
     });
   }

4. PUSH HEADER VALIDATION:
   Validate push headers:

   function validatePushHeaders(headers) {
     const allowedHeaders = [
       'content-type',
       'content-length',
       'cache-control',
       'etag',
       'last-modified'
     ];

     for (const header in headers) {
       if (!allowedHeaders.includes(header.toLowerCase())) {
         throw new Error('Invalid push header: ' + header);
       }

       // Validate header values
       const cleanValue = DOMPurify.sanitize(headers[header]);
       headers[header] = cleanValue;
     }

     return headers;
   }

5. PUSH DEPENDENCY VALIDATION:
   Validate push dependencies:

   function validatePushDependencies(dependencies) {
     return dependencies.every(dep => {
       return validatePushPath(dep.path) &&
              isValidContentType(dep.contentType) &&
              dep.content.length < MAX_PUSH_SIZE;
     });
   }

6. CACHE SECURITY:
   Secure push cache handling:

   function cachePushResource(path, content) {
     const cleanPath = validatePushPath(path);
     const cleanContent = sanitizePushContent(content, getContentType(cleanPath));

     // Store with validation
     cache.set(cleanPath, {
       content: cleanContent,
       timestamp: Date.now(),
       validated: true
     });
   }

7. RATE LIMITING:
   Implement push rate limiting:

   const pushLimits = new Map();

   function canPushForUser(userId) {
     const userPushes = pushLimits.get(userId) || 0;
     const now = Date.now();

     // Reset counter every minute
     if (now - (pushLimits.get(userId + '_time') || 0) > 60000) {
       pushLimits.set(userId, 0);
       pushLimits.set(userId + '_time', now);
     }

     if (userPushes >= MAX_PUSHES_PER_MINUTE) {
       return false;
     }

     pushLimits.set(userId, userPushes + 1);
     return true;
   }

8. ORIGIN VALIDATION:
   Validate push origins:

   function validatePushOrigin(origin) {
     const allowedOrigins = [
       'https://yourdomain.com',
       'https://cdn.yourdomain.com',
       'https://api.yourdomain.com'
     ];

     return allowedOrigins.includes(origin);
   }

9. SETTINGS FRAME SECURITY:
   Secure HTTP/2 settings:

   const secureSettings = {
     SETTINGS_HEADER_TABLE_SIZE: 4096,
     SETTINGS_ENABLE_PUSH: 1,  // Enable push
     SETTINGS_MAX_CONCURRENT_STREAMS: 100,
     SETTINGS_INITIAL_WINDOW_SIZE: 65535,
     SETTINGS_MAX_FRAME_SIZE: 16384,
     SETTINGS_MAX_HEADER_LIST_SIZE: 8192
   };

   // Don't allow user control over settings
   function validateSettings(settings) {
     for (const key in settings) {
       if (typeof settings[key] !== 'number' || settings[key] < 0) {
         throw new Error('Invalid settings value');
       }
     }
     return settings;
   }

10. COMPRESSION SECURITY:
    Secure HPACK compression:

    function validateCompressedHeaders(compressedData) {
      // Validate compression format
      if (!isValidHPACKFormat(compressedData)) {
        throw new Error('Invalid compression format');
      }

      // Decompress and validate
      const decompressed = hpack.decode(compressedData);
      return validatePushHeaders(decompressed);
    }

11. PUSH PROMISE VALIDATION:
    Validate push promises:

    function validatePushPromise(promise) {
      if (!promise.path || typeof promise.path !== 'string') {
        throw new Error('Invalid push promise path');
      }

      const cleanPath = validatePushPath(promise.path);

      if (promise.headers) {
        promise.headers = validatePushHeaders(promise.headers);
      }

      return {...promise, path: cleanPath};
    }

12. CSP FOR HTTP/2 PUSH:
    Content Security Policy:

    Content-Security-Policy:
      default-src 'self';
      script-src 'self';
      style-src 'self' 'unsafe-inline';
      img-src 'self' data: https:;
      connect-src 'self';
      push-src 'self';  // HTTP/2 Push policy

13. LOGGING AND MONITORING:
    Comprehensive HTTP/2 monitoring:

    function logPushOperation(operation, details) {
      logger.info('HTTP/2 Push operation', {
        operation: operation,
        path: details.path,
        contentType: details.contentType,
        size: details.content ? details.content.length : 0,
        timestamp: new Date().toISOString(),
        userAgent: details.userAgent
      });
    }

14. ERROR HANDLING:
    Secure error handling:

    server.onPushError = function(error, stream) {
      logger.error('HTTP/2 Push error', {
        error: error.message,
        streamId: stream.id
      });

      // Don't push error details
      stream.push('/error.html', genericErrorPage);
    };

15. TESTING AND VALIDATION:
    Regular security testing:

    Automated tests:
    - HTTP/2 push validation
    - Push content sanitization
    - Cache security testing
    - Compression validation

    Manual tests:
    - Browser DevTools Network inspection
    - Push promise monitoring
    - Server push configuration testing

SECURITY TESTING PAYLOADS:

Basic HTTP/2 Push XSS:
<script>alert('Push XSS')</script>
<img src=x onerror=alert(1)>
<svg onload=alert(1)>

Push path injection:
/api/user/<script>alert(1)</script>
/assets/<script>alert(1)</script>.css
/static/<img src=x onerror=alert(1)>.js

Push content injection:
var userName = "<script>alert(1)</script>";
console.log("<script>alert(1)</script>");

Advanced payloads:
javascript:/*--></title></style></textarea></script></xmp><svg/onload=alert(1)>
data:text/html,<script>alert(1)</script>
vbscript:msgbox(1)

HTTP/2 PUSH SECURITY HEADERS:

HTTP/2-Settings: (secure settings)
Cache-Control: no-cache, no-store
Content-Security-Policy: push-src 'self'
X-Content-Type-Options: nosniff

MONITORING METRICS:

Monitor for:
- Unusual push patterns
- Large push content
- Push path anomalies
- Cache corruption attempts
- Rate limiting violations

OWASP REFERENCES:
- OWASP HTTP/2 Security Cheat Sheet
- HTTP/2 Server Push Security
- Web Performance Optimization Security
- CDN Security Best Practices
""",
}

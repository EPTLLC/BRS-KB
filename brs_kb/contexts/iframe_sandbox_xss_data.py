#!/usr/bin/env python3

"""
Project: BRS-KB (BRS XSS Knowledge Base)
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: 2025-12-04 19:21:27 UTC
Status: Created
Telegram: https://t.me/easyprotech

iframe Sandbox XSS Context - Data Module
Contains description and remediation data
"""

DESCRIPTION = """
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
"""

REMEDIATION = """
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

#!/usr/bin/env python3

"""
Project: BRS-KB (BRS XSS Knowledge Base)
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: 2025-12-04 19:21:27 UTC
Status: Created
Telegram: https://t.me/easyprotech

Cross-Site Scripting (XSS) in Shadow DOM Context - Data Module
Contains description and remediation data
"""

DESCRIPTION = """
Shadow DOM XSS occurs when user input is reflected into Shadow DOM elements or when Shadow DOM
boundaries are manipulated to break encapsulation. Shadow DOM provides encapsulation for web
components, but when malicious content is injected into shadow trees or when shadow boundaries
are crossed inappropriately, it can lead to XSS attacks that bypass traditional DOM protections.

VULNERABILITY CONTEXT:
Shadow DOM XSS typically happens when:
1. User content is inserted into shadow DOM without sanitization
2. Component slots contain malicious content
3. Shadow DOM templates are dynamically generated
4. Custom element attributes contain executable code
5. Shadow root mode is manipulated
6. Event delegation across shadow boundaries

Common in:
- Web Components frameworks (Lit, FAST, Stencil)
- UI component libraries
- Custom element implementations
- Widget systems
- Plugin architectures
- Template engines
- Component-based applications

SEVERITY: HIGH
Shadow DOM XSS can bypass traditional XSS protections and Content Security Policies in some cases.
The encapsulation makes detection challenging, and attacks can persist within component boundaries.
"""

REMEDIATION = """
SHADOW DOM XSS DEFENSE STRATEGY:

1. CONTENT SANITIZATION (PRIMARY DEFENSE):
   Sanitize all content before inserting into Shadow DOM:

   JavaScript sanitization:
   function sanitizeForShadowDOM(content) {
     if (typeof content !== 'string') return content;

     return DOMPurify.sanitize(content, {
       ALLOWED_TAGS: ['b', 'i', 'em', 'strong', 'span'],
       ALLOWED_ATTR: ['class', 'id', 'title']
     });
   }

   Python backend:
   import bleach
   clean_content = bleach.clean(user_content, tags=['b', 'i', 'em'], strip=True)

2. SLOT CONTENT VALIDATION:
   Validate content in named slots:

   class SecureComponent extends HTMLElement {
     connectedCallback() {
       const nameSlot = this.querySelector('[slot="name"]');
       if (nameSlot) {
         const cleanContent = sanitizeForShadowDOM(nameSlot.textContent);
         this.shadowRoot.getElementById('name-display').textContent = cleanContent;
       }
     }
   }

3. CUSTOM ELEMENT SECURITY:
   Secure custom element implementation:

   class SecureElement extends HTMLElement {
     constructor() {
       super();
       this.attachShadow({mode: 'open'});

       // Use textContent instead of innerHTML
       this.shadowRoot.textContent = 'Loading...';

       // Validate all attributes
       this.validateAttributes();
     }

     validateAttributes() {
       const attributes = ['title', 'data-value', 'aria-label'];
       attributes.forEach(attr => {
         const value = this.getAttribute(attr);
         if (value) {
           const cleanValue = sanitizeForShadowDOM(value);
           this.setAttribute(attr, cleanValue);
         }
       });
     }
   }

4. TEMPLATE SECURITY:
   Secure template usage:

   const secureTemplate = document.createElement('template');
   const cleanHTML = sanitizeForShadowDOM(userHTML);
   secureTemplate.innerHTML = cleanHTML;

   // Clone and use securely
   const content = secureTemplate.content.cloneNode(true);
   this.shadowRoot.appendChild(content);

5. ATTRIBUTE VALIDATION:
   Validate all element attributes:

   function validateElementAttributes(element) {
     const attributes = element.attributes;

     for (let i = 0; i < attributes.length; i++) {
       const attr = attributes[i];
       const cleanValue = sanitizeForShadowDOM(attr.value);

       if (cleanValue !== attr.value) {
         element.setAttribute(attr.name, cleanValue);
       }
     }
   }

6. SHADOW DOM MODE SECURITY:
   Use appropriate shadow DOM modes:

   // For public components, use 'open' mode
   this.attachShadow({mode: 'open'});

   // For secure components, use 'closed' mode
   this.attachShadow({mode: 'closed'});

   // But validate content regardless of mode

7. EVENT HANDLER SECURITY:
   Secure event handling across shadow boundaries:

   this.shadowRoot.addEventListener('click', function(event) {
     const target = event.target;

     // Validate target before processing
     if (!isValidTarget(target)) {
       event.stopPropagation();
       return;
     }

     // Safe event processing
     handleClick(target);
   });

8. CSS CUSTOM PROPERTIES SECURITY:
   Secure CSS custom properties:

   function setSecureCustomProperty(property, value) {
     const cleanValue = sanitizeForShadowDOM(value);

     // Validate property name
     if (!isValidCSSProperty(property)) {
       throw new Error('Invalid CSS property');
     }

     this.shadowRoot.style.setProperty(property, cleanValue);
   }

9. COMPONENT REGISTRY SECURITY:
   Secure custom element registration:

   function registerSecureComponent(name, componentClass) {
     // Validate component name
     if (!isValidComponentName(name)) {
       throw new Error('Invalid component name');
     }

     // Validate component class
     if (!isSecureComponent(componentClass)) {
       throw new Error('Insecure component class');
     }

     customElements.define(name, componentClass);
   }

10. SHADOW DOM BOUNDARY PROTECTION:
    Protect shadow DOM boundaries:

    // Prevent external access to shadow DOM
    Object.defineProperty(this, 'shadowRoot', {
      get: function() {
        if (this.mode === 'closed') {
          return null;  // Hide closed shadow DOM
        }
        return this.__shadowRoot;
      }
    });

11. INPUT VALIDATION:
    Comprehensive input validation:

    const VALIDATION_RULES = {
      maxLength: 1000,
      allowedChars: /^[a-zA-Z0-9\\s\\.,!?\\-_]+$/,
      blockedPatterns: [
        /<script\b[^<]*(?:(?!<\\/script>)<[^<]*)*<\\/script>/gi,
        /javascript:/gi,
        /vbscript:/gi,
        /on\\w+\\s*=/gi
      ]
    };

12. CSP FOR SHADOW DOM:
    Content Security Policy:

    Content-Security-Policy:
      default-src 'self';
      script-src 'self' 'nonce-{random}';
      style-src 'self' 'unsafe-inline';  // For component styles
      connect-src 'self';
      object-src 'none';

13. ERROR HANDLING:
    Secure error handling:

    try {
      this.shadowRoot.innerHTML = userContent;
    } catch (error) {
      logger.error('Shadow DOM error', {
        error: error.message,
        component: this.tagName
      });

      // Show safe fallback
      this.shadowRoot.innerHTML = '<div>Safe content</div>';
    }

14. LOGGING AND MONITORING:
    Comprehensive Shadow DOM monitoring:

    function logComponentEvent(event, details) {
      logger.info('Component event', {
        event: event,
        component: details.tagName,
        timestamp: new Date().toISOString()
      });
    }

15. TESTING AND VALIDATION:
    Regular security testing:

    Automated tests:
    - Shadow DOM content validation
    - Slot content testing
    - Component attribute testing
    - Boundary crossing validation

    Manual tests:
    - DevTools Shadow DOM inspection
    - Component property testing
    - Template security analysis

SECURITY TESTING PAYLOADS:

Basic Shadow DOM XSS:
<script>alert('Shadow DOM XSS')</script>
<img src=x onerror=alert(1)>
<svg onload=alert(1)>

Slot injection:
<span slot="content"><script>alert(1)</script></span>
<div slot="header"><img src=x onerror=alert(1)></div>

Attribute injection:
<my-component data-value="<script>alert(1)</script>"></my-component>
<user-profile title="<img src=x onerror=alert(1)>"></user-profile>

Advanced payloads:
javascript:alert(1)
data:text/html,<script>alert(1)</script>
vbscript:msgbox(1)

SHADOW DOM SECURITY HEADERS:

Content-Security-Policy: default-src 'self'
X-Content-Type-Options: nosniff
X-Shadow-DOM-Mode: secure

MONITORING METRICS:

Monitor for:
- Shadow DOM creation patterns
- Custom element registration
- Slot content anomalies
- Component attribute changes
- Boundary crossing attempts

OWASP REFERENCES:
- OWASP Web Components Security
- OWASP Shadow DOM Cheat Sheet
- Web Components Security Best Practices
- DOM Encapsulation Security
"""

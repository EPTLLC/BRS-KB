#!/usr/bin/env python3

"""
Project: BRS-KB (BRS XSS Knowledge Base)
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: 2025-12-04 19:21:27 UTC
Status: Created
Telegram: https://t.me/easyprotech

Custom Elements XSS Context - Data Module
Contains description and remediation data
"""

DESCRIPTION = """
Custom Elements XSS occurs when user input is reflected into Custom Element definitions, attributes,
or lifecycle callbacks without proper sanitization. Custom Elements are part of the Web Components
specification that allows developers to create reusable HTML elements with custom behavior.
When malicious content is injected into element names, attributes, or callback functions, it can
lead to XSS attacks that can be persistent and affect multiple instances of the element.

VULNERABILITY CONTEXT:
Custom Elements XSS typically happens when:
1. Element names contain malicious content
2. Element attributes are reflected without sanitization
3. Lifecycle callbacks execute user-controlled code
4. Template content is dynamically generated
5. Element properties contain executable content
6. Custom element registry is manipulated

Common in:
- Web Components frameworks (Lit, Stencil, FAST)
- UI component libraries
- Widget platforms
- Plugin systems
- Template engines
- Dynamic component systems
- Custom element marketplaces

SEVERITY: HIGH
Custom Elements XSS can affect multiple instances of components and persist across page loads.
The dynamic nature of custom elements makes detection challenging, and attacks can spread
through component libraries and frameworks.
"""

REMEDIATION = r"""
CUSTOM ELEMENTS XSS DEFENSE STRATEGY:

1. ELEMENT NAME VALIDATION (PRIMARY DEFENSE):
   Validate custom element names:

   function isValidElementName(name) {
     // Must start with lowercase letter
     if (!/^[a-z]/.test(name)) return false;

     // Must contain only lowercase letters, numbers, and hyphens
     if (!/^[a-z0-9-]+$/.test(name)) return false;

     // Must not contain XSS patterns
     const dangerousPatterns = [
       /script/i,
       /javascript/i,
       /vbscript/i,
       /on\w+/i
     ];

     for (const pattern of dangerousPatterns) {
       if (pattern.test(name)) return false;
     }

     // Length limits
     if (name.length > 50) return false;

     return true;
   }

2. ATTRIBUTE SANITIZATION:
   Sanitize all element attributes:

   function sanitizeElementAttributes(element) {
     const attributes = Array.from(element.attributes);

     attributes.forEach(attr => {
       const cleanValue = DOMPurify.sanitize(attr.value, {
         ALLOWED_TAGS: [],
         ALLOWED_ATTR: ['class', 'id', 'data-*']
       });

       if (cleanValue !== attr.value) {
         element.setAttribute(attr.name, cleanValue);
       }
     });
   }

3. LIFECYCLE CALLBACK SECURITY:
   Secure lifecycle implementations:

   class SecureComponent extends HTMLElement {
     connectedCallback() {
       // Validate element state
       this.validateState();

       // Safe rendering
       this.renderSecurely();
     }

     validateState() {
       // Validate all attributes and properties
       const title = this.getAttribute('title');
       if (title) {
         const cleanTitle = DOMPurify.sanitize(title);
         this.setAttribute('title', cleanTitle);
       }
     }

     renderSecurely() {
       // Use safe rendering methods
       const title = this.getAttribute('title');
       this.shadowRoot.textContent = title || 'Default Title';
     }
   }

4. CUSTOM ELEMENT REGISTRY SECURITY:
   Secure element registration:

   function registerSecureElement(name, componentClass) {
     // Validate element name
     if (!isValidElementName(name)) {
       throw new Error('Invalid element name');
     }

     // Validate component class
     if (!isSecureComponentClass(componentClass)) {
       throw new Error('Insecure component class');
     }

     // Check if element already exists
     if (customElements.get(name)) {
       throw new Error('Element already registered');
     }

     customElements.define(name, componentClass);
   }

5. TEMPLATE SECURITY:
   Secure template usage:

   function createSecureTemplate(html) {
     const cleanHTML = DOMPurify.sanitize(html, {
       ALLOWED_TAGS: ['div', 'span', 'p', 'h1', 'h2', 'h3', 'slot'],
       ALLOWED_ATTR: ['class', 'id', 'slot']
     });

     const template = document.createElement('template');
     template.innerHTML = cleanHTML;
     return template;
   }

6. OBSERVED ATTRIBUTES VALIDATION:
   Secure attribute observation:

   static get observedAttributes() {
     return ['title', 'data-value', 'aria-label'];  // Fixed list only
   }

   attributeChangedCallback(name, oldValue, newValue) {
     // Validate new value
     const cleanValue = DOMPurify.sanitize(newValue);

     // Update safely
     this.setAttribute(name, cleanValue);

     // Re-render safely
     this.render();
   }

7. PROTOTYPE PROTECTION:
   Protect element prototypes:

   // Prevent prototype pollution
   Object.freeze(HTMLElement.prototype);

   // Custom prototype protection
   const originalDefine = customElements.define;
   customElements.define = function(name, constructor, options) {
     // Validate before registration
     if (!isValidElementName(name)) {
       throw new Error('Invalid element name');
     }

     return originalDefine.call(this, name, constructor, options);
   };

8. INPUT VALIDATION:
   Comprehensive input validation:

   const VALIDATION_PATTERNS = {
     elementName: /^[a-z][a-z0-9-]*$/,
     attributeName: /^[a-zA-Z][a-zA-Z0-9-_]*$/,
     attributeValue: /^[^<>"'&]*$/
   };

   function validateCustomElementInput(input, type) {
     const pattern = VALIDATION_PATTERNS[type];
     if (!pattern.test(input)) {
       throw new Error('Invalid input for ' + type);
     }
     return input;
   }

9. CSP FOR CUSTOM ELEMENTS:
   Content Security Policy:

   Content-Security-Policy:
     default-src 'self';
     script-src 'self' 'nonce-{random}';
     style-src 'self' 'unsafe-inline';  // For component styles
     connect-src 'self';
     object-src 'none';

10. ERROR HANDLING:
    Secure error handling:

    try {
      customElements.define(name, componentClass);
    } catch (error) {
      logger.error('Custom element registration failed', {
        elementName: name,
        error: error.message
      });

      // Don't expose errors to users
      showGenericError();
    }

11. LOGGING AND MONITORING:
    Comprehensive monitoring:

    function logElementEvent(event, elementName, details) {
      logger.info('Custom element event', {
        event: event,
        elementName: elementName,
        details: details,
        timestamp: new Date().toISOString()
      });
    }

12. REGISTRY PROTECTION:
    Protect custom elements registry:

    // Prevent registry manipulation
    Object.defineProperty(window, 'customElements', {
      value: customElements,
      writable: false,
      configurable: false
    });

13. CONSTRUCTOR SECURITY:
    Secure element constructors:

    class SecureComponent extends HTMLElement {
      constructor() {
        super();

        // Validate constructor context
        if (!this.isConnected) {
          throw new Error('Component must be connected to DOM');
        }

        this.initSecurely();
      }

      initSecurely() {
        // Safe initialization
        this.shadowRoot.innerHTML = '<div>Loading...</div>';
      }
    }

14. ATTRIBUTE CHANGE SECURITY:
    Secure attribute changes:

    attributeChangedCallback(name, oldValue, newValue) {
      // Validate attribute name and value
      if (!isValidAttributeName(name)) {
        return;  // Ignore invalid attributes
      }

      const cleanValue = DOMPurify.sanitize(newValue);
      this.setAttribute(name, cleanValue);

      // Safe update
      this.updateDisplay();
    }

15. TESTING AND VALIDATION:
    Regular security testing:

    Automated tests:
    - Custom element validation
    - Attribute injection testing
    - Lifecycle security testing
    - Registry manipulation testing

    Manual tests:
    - DevTools custom elements inspection
    - Component behavior testing
    - Registry state analysis

SECURITY TESTING PAYLOADS:

Basic Custom Elements XSS:
<script>alert('Custom Element XSS')</script>
<img src=x onerror=alert(1)>
<svg onload=alert(1)>

Element name injection:
x-script-alert-1
my-script-tag
custom-img-src-x-onerror-alert-1

Attribute injection:
<my-component title="<script>alert(1)</script>"></my-component>
<user-widget data-value="<img src=x onerror=alert(1)>"></user-widget>

Advanced payloads:
javascript:alert(1)
data:text/html,<script>alert(1)</script>
vbscript:msgbox(1)

CUSTOM ELEMENTS SECURITY HEADERS:

Content-Security-Policy: default-src 'self'
X-Content-Type-Options: nosniff
X-Custom-Elements-Mode: secure

MONITORING METRICS:

Monitor for:
- Custom element registration patterns
- Element name anomalies
- Attribute value patterns
- Lifecycle callback execution
- Registry state changes

OWASP REFERENCES:
- OWASP Web Components Security
- OWASP Custom Elements Cheat Sheet
- Web Components Security Best Practices
- HTML5 Custom Elements Security
"""

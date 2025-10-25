#!/usr/bin/env python3

"""
Project: BRS-KB (BRS XSS Knowledge Base)
Company: EasyProTech LLC (www.easyprotech)
Dev: Brabus
Date: Sat 25 Oct 2025 12:00:00 UTC
Status: Created
Telegram: https://t.me/easyprotech

Knowledge Base: Custom Elements XSS Context - Comprehensive Guide
"""

DETAILS = {
    "title": "Cross-Site Scripting (XSS) in Custom Elements Context",
    # Metadata for SIEM/Triage Integration
    "severity": "high",
    "cvss_score": 7.1,
    "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N",
    "reliability": "certain",
    "cwe": ["CWE-79"],
    "owasp": ["A03:2021"],
    "tags": ["xss", "custom-elements", "web-components", "html-injection", "modern-web"],
    "description": """
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
""",
    "attack_vector": """
CUSTOM ELEMENTS XSS ATTACK VECTORS:

1. ELEMENT TAG NAME INJECTION:
   Dynamic element creation:
   const tagName = USER_INPUT;  // Element name injection
   customElements.define(tagName, MyComponent);

   Attack payload:
   <script>alert(1)</script>

   Result: <script>alert(1)</script> becomes a valid custom element

2. ATTRIBUTE REFLECTION:
   Custom element with reflected attributes:
   <my-widget title="USER_INPUT"></my-widget>

   Component code:
   connectedCallback() {
     this.shadowRoot.innerHTML = '<h1>' + this.getAttribute('title') + '</h1>';
   }

3. PROPERTY INJECTION:
   Element properties with XSS:
   class MyComponent extends HTMLElement {
     set userData(value) {
       this._userData = value;
       this.render();  // Triggers re-render
     }

     render() {
       this.shadowRoot.innerHTML = '<div>' + this._userData + '</div>';
     }
   }

4. LIFECYCLE CALLBACK INJECTION:
   Lifecycle methods with XSS:
   connectedCallback() {
     // USER_INPUT executed here
     eval(USER_INPUT);
   }

   disconnectedCallback() {
     // Cleanup with potential XSS
     document.body.innerHTML = USER_INPUT;
   }

5. OBSERVED ATTRIBUTES INJECTION:
   Observed attributes with XSS:
   static get observedAttributes() {
     return [USER_INPUT];  // Attribute name injection
   }

   attributeChangedCallback(name, oldValue, newValue) {
     this.shadowRoot.innerHTML = '<div>' + newValue + '</div>';
   }

ADVANCED CUSTOM ELEMENTS XSS TECHNIQUES:

6. CUSTOM ELEMENT CONSTRUCTOR INJECTION:
   Constructor with XSS:
   constructor() {
     super();
     this.shadowRoot.innerHTML = USER_INPUT;  // Constructor injection
   }

7. PROTOTYPE POLLUTION:
   Modifying element prototypes:
   HTMLElement.prototype.connectedCallback = function() {
     // Malicious callback injected
     eval(USER_INPUT);
   };

8. GLOBAL REGISTRY MANIPULATION:
   Custom element registry injection:
   const registry = customElements;
   registry.define(USER_INPUT, MaliciousComponent);  // Registry injection

9. ELEMENT UPGRADE INJECTION:
   Element upgrade with XSS:
   const element = document.createElement('div');
   element.innerHTML = USER_INPUT;  // Pre-upgrade injection

   customElements.define('my-element', MyComponent);
   element.setAttribute('is', 'my-element');  // Upgrade with XSS

10. TEMPLATE CONTENT INJECTION:
    Template with dynamic content:
    const template = document.createElement('template');
    template.innerHTML = '<div><slot>' + USER_INPUT + '</slot></div>';

    const content = template.content.cloneNode(true);
    this.shadowRoot.appendChild(content);

11. CUSTOM EVENT INJECTION:
    Custom events with XSS:
    this.dispatchEvent(new CustomEvent('user-action', {
      detail: {data: USER_INPUT}  // Event data injection
    }));

12. STYLE INJECTION:
    Component styles with XSS:
    const style = document.createElement('style');
    style.textContent = ':host { background: url(' + USER_INPUT + '); }';

    this.shadowRoot.appendChild(style);

13. SLOT DEFAULT CONTENT INJECTION:
    Default slot content:
    <template>
      <div class="component">
        <slot>USER_INPUT</slot>  <!-- Default slot XSS -->
      </div>
    </template>

14. FORM-ASSOCIATED ELEMENTS:
    Form elements with XSS:
    class MyInput extends HTMLElement {
      connectedCallback() {
        this.innerHTML = '<input value="' + USER_INPUT + '">';  // Input value XSS
      }
    }

15. AUTONOMOUS VS CUSTOMIZED ELEMENTS:
    Element type confusion:
    // Autonomous element
    customElements.define('my-autonomous', MyComponent);

    // Customized built-in element
    customElements.define('my-input', MyInput, {extends: 'input'});

    // XSS in extended element
    <input is="my-input" value="USER_INPUT">

CUSTOM ELEMENTS-SPECIFIC BYPASSES:

16. ELEMENT NAME VALIDATION BYPASS:
    Valid element names with XSS:
    const validName = 'x-script-alert-1';  // Valid name with XSS
    customElements.define(validName, MyComponent);

17. ATTRIBUTE NAME INJECTION:
    Dynamic attribute names:
    const attrName = USER_INPUT;  // Attribute name XSS
    element.setAttribute(attrName, 'value');

18. PROTOTYPE CHAIN POLLUTION:
    Modifying prototype chain:
    Object.prototype.innerHTML = USER_INPUT;  // Global pollution

19. CONSTRUCTOR NAME INJECTION:
    Constructor name with XSS:
    class MaliciousComponent extends HTMLElement {
      constructor() {
        super();
        this.constructor.name = USER_INPUT;  // Constructor name XSS
      }
    }

20. SYMBOL PROPERTY INJECTION:
    Symbol properties with XSS:
    const maliciousSymbol = Symbol(USER_INPUT);  // Symbol injection
    element[maliciousSymbol] = 'XSS';

REAL-WORLD ATTACK SCENARIOS:

21. COMPONENT LIBRARY ATTACK:
    - Third-party component library
    - Component name: <script>alert(1)</script>
    - Library registration
    - Affects all library users

22. WIDGET PLATFORM:
    - Embeddable widget system
    - Widget type: <script>alert(1)</script>
    - Widget registration
    - Platform-wide XSS

23. PLUGIN SYSTEM:
    - Extensible application
    - Plugin name: <script>alert(1)</script>
    - Plugin loading
    - Application compromise

24. FORM BUILDER:
    - Dynamic form generation
    - Field type: <script>alert(1)</script>
    - Form field creation
    - Form submission hijacking

25. DASHBOARD SYSTEM:
    - Configurable dashboard
    - Widget name: <script>alert(1)</script>
    - Widget instantiation
    - Dashboard compromise

26. THEME SYSTEM:
    - Customizable themes
    - Component name: <script>alert(1)</script>
    - Theme application
    - UI corruption

27. E-COMMERCE PLATFORM:
    - Product customization
    - Custom element: <script>alert(1)</script>
    - Product display
    - Shopping cart manipulation

CUSTOM ELEMENTS XSS DETECTION:

28. MANUAL TESTING:
    - DevTools Elements inspection
    - Custom elements registry inspection
    - Component lifecycle testing
    - Attribute manipulation testing

29. AUTOMATED SCANNING:
    - Custom elements registry analysis
    - Component definition validation
    - Attribute injection testing
    - Lifecycle callback testing

30. BROWSER EXTENSIONS:
    - Custom elements monitoring
    - Component analysis tools
    - Registry inspection extensions
""",
    "remediation": """
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
""",
}

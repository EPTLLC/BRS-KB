#!/usr/bin/env python3

"""
Project: BRS-KB (BRS XSS Knowledge Base)
Company: EasyProTech LLC (www.easyprotech)
Dev: Brabus
Date: Sat 25 Oct 2025 12:00:00 UTC
Status: Created
Telegram: https://t.me/easyprotech

Knowledge Base: Shadow DOM XSS Context - Comprehensive Guide
"""

DETAILS = {
    "title": "Cross-Site Scripting (XSS) in Shadow DOM Context",

    # Metadata for SIEM/Triage Integration
    "severity": "high",
    "cvss_score": 7.3,
    "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N",
    "reliability": "certain",
    "cwe": ["CWE-79"],
    "owasp": ["A03:2021"],
    "tags": ["xss", "shadow-dom", "web-components", "encapsulation", "modern-web"],

    "description": """
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
""",

    "attack_vector": """
SHADOW DOM XSS ATTACK VECTORS:

1. SLOT CONTENT INJECTION:
   Custom element with slot:
   <user-profile>
     <span slot="name">USER_INPUT</span>  <!-- Slot injection -->
   </user-profile>

   Component template:
   <template>
     <div class="profile">
       <h2><slot name="name"></slot></h2>  <!-- XSS in slot -->
     </div>
   </template>

2. SHADOW DOM INNER HTML INJECTION:
   Direct shadow DOM manipulation:
   const shadow = element.attachShadow({mode: 'open'});
   shadow.innerHTML = USER_INPUT;  // Direct injection

3. CUSTOM ELEMENT ATTRIBUTE INJECTION:
   Custom element attributes:
   <my-component title="USER_INPUT"></my-component>

   Component code:
   connectedCallback() {
     this.shadowRoot.innerHTML = '<h1>' + this.getAttribute('title') + '</h1>';
   }

4. TEMPLATE SLOT INJECTION:
   Template with dynamic slots:
   const template = document.createElement('template');
   template.innerHTML = USER_INPUT;  <!-- Template injection -->

   const shadow = element.attachShadow({mode: 'open'});
   shadow.appendChild(template.content.cloneNode(true));

5. SHADOW ROOT MODE MANIPULATION:
   Shadow root mode injection:
   const shadow = element.attachShadow({
     mode: USER_INPUT  // Mode injection
   });

   Attack payload:
   'open<script>alert(1)</script>'

ADVANCED SHADOW DOM XSS TECHNIQUES:

6. CUSTOM ELEMENT TAG NAME INJECTION:
   Creating elements with XSS names:
   const tagName = USER_INPUT;  // Tag name injection
   customElements.define(tagName, MyComponent);

   Attack payload:
   <script>alert(1)</script>

7. CONSTRUCTOR INJECTION:
   Custom element constructor injection:
   class MaliciousComponent extends HTMLElement {
     constructor() {
       super();
       this.shadowRoot.innerHTML = USER_INPUT;  // Constructor injection
     }
   }

8. ATTRIBUTE OBSERVER INJECTION:
   Mutation observer with XSS:
   const observer = new MutationObserver(function(mutations) {
     mutations.forEach(function(mutation) {
       if (mutation.type === 'attributes') {
         const value = mutation.target.getAttribute('data-user');
         this.shadowRoot.getElementById('display').innerHTML = value;  // XSS
       }
     });
   });

9. EVENT LISTENER INJECTION:
   Event delegation across shadow boundaries:
   element.addEventListener('click', function(event) {
     const target = event.target;
     if (target.matches(USER_INPUT)) {  // Selector injection
       // XSS execution
     }
   });

10. CSS CUSTOM PROPERTY INJECTION:
    Shadow DOM styles with XSS:
    const style = document.createElement('style');
    style.textContent = ':host { --user-color: ' + USER_INPUT + '; }';  // CSS injection

    this.shadowRoot.appendChild(style);

11. SHADOW DOM QUERY SELECTOR INJECTION:
    Querying shadow DOM with XSS:
    const selector = USER_INPUT;  // Selector injection
    const elements = this.shadowRoot.querySelectorAll(selector);

12. FRAGMENT DIRECTIVE INJECTION:
    Shadow DOM template fragments:
    const template = document.createElement('template');
    template.innerHTML = '<div>' + USER_INPUT + '</div>';  // Fragment injection

13. SHADOW ROOT ADOPTION:
    Adopting shadow trees with XSS:
    const shadowTree = document.createElement('div');
    shadowTree.innerHTML = USER_INPUT;  // Tree injection

    const shadow = element.attachShadow({mode: 'open'});
    shadow.appendChild(shadowTree);

14. CUSTOM ELEMENT REGISTRY INJECTION:
    Global registry manipulation:
    const componentName = USER_INPUT;  // Component name injection
    customElements.define(componentName, MaliciousComponent);

15. SHADOW BOUNDARY CROSSING:
    Crossing shadow boundaries:
    const host = document.querySelector('my-component');
    const shadow = host.shadowRoot;

    // Inject into shadow from outside
    const slot = shadow.querySelector('slot');
    slot.innerHTML = USER_INPUT;  // Boundary crossing

SHADOW DOM-SPECIFIC BYPASSES:

16. CLOSED SHADOW DOM ESCAPE:
    Escaping closed shadow boundaries:
    const shadow = element.attachShadow({mode: 'closed'});
    shadow.innerHTML = USER_INPUT;  // Still vulnerable to injection

17. TEMPLATE CLONING ATTACK:
    Template cloning with XSS:
    const template = document.createElement('template');
    template.innerHTML = '<div><slot></slot></div>';

    const clone = template.content.cloneNode(true);
    clone.querySelector('slot').innerHTML = USER_INPUT;  // Clone injection

18. FRAGMENT COMPOSITION:
    Multiple fragments with coordinated attack:
    fragment1.innerHTML = '<div>';
    fragment2.innerHTML = USER_INPUT;  // XSS fragment
    fragment3.innerHTML = '</div>';

19. ATTRIBUTE REFLECTION:
    Reflecting attributes through shadow DOM:
    const attribute = element.getAttribute('data-user');
    this.shadowRoot.innerHTML = '<span data-value="' + attribute + '"></span>';

20. EVENT BUBBLING MANIPULATION:
    Event bubbling through shadow boundaries:
    this.shadowRoot.addEventListener('custom-event', function(event) {
      document.body.innerHTML = event.detail.data;  // XSS through events
    });

REAL-WORLD ATTACK SCENARIOS:

21. UI COMPONENT LIBRARY:
    - Third-party component library
    - Component props: <script>alert(1)</script>
    - Rendered in shadow DOM
    - Affects all library users

22. WIDGET PLATFORM:
    - Embeddable widgets
    - Widget config: <script>alert(1)</script>
    - Widget rendered in shadow DOM
    - Affects all widget consumers

23. PLUGIN SYSTEM:
    - Browser extension plugins
    - Plugin manifest: <script>alert(1)</script>
    - Plugin UI in shadow DOM
    - Extension compromise

24. WEB COMPONENT FRAMEWORK:
    - Lit, FAST, or Stencil components
    - Component properties: <script>alert(1)</script>
    - Template rendering
    - Framework-wide XSS

25. DASHBOARD WIDGETS:
    - Configurable dashboard
    - Widget title: <script>alert(1)</script>
    - Widget content in shadow DOM
    - Dashboard compromise

26. FORM BUILDER:
    - Dynamic form generation
    - Field label: <script>alert(1)</script>
    - Form fields in shadow DOM
    - Form submission hijacking

27. CHAT WIDGET:
    - Live chat component
    - User message: <script>alert(1)</script>
    - Message display in shadow DOM
    - Chat session hijacking

SHADOW DOM XSS DETECTION:

28. MANUAL TESTING:
    - DevTools Elements inspection
    - Shadow DOM expansion in DevTools
    - Component property testing
    - Event listener monitoring

29. AUTOMATED SCANNING:
    - Shadow DOM tree traversal
    - Component property injection
    - Template analysis
    - Encapsulation testing

30. BROWSER EXTENSIONS:
    - Shadow DOM inspection tools
    - Component analysis extensions
    - DOM tree visualization
""",

    "remediation": """
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
      allowedChars: /^[a-zA-Z0-9\s\.,!?\-_]+$/,
      blockedPatterns: [
        /<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>/gi,
        /javascript:/gi,
        /vbscript:/gi,
        /on\w+\s*=/gi
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
}

#!/usr/bin/env python3

"""
Project: BRS-KB (BRS XSS Knowledge Base)
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: 2025-12-04 19:21:27 UTC
Status: Created
Telegram: https://t.me/easyprotech

Custom Elements XSS Context - Attack Vectors Module
"""

ATTACK_VECTOR = """
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
"""

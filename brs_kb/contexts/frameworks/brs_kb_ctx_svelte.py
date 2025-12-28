#!/usr/bin/env python3
# Project: BRS-KB
# Company: EasyProTech LLC (www.easypro.tech)
# Dev: Brabus
# Date: 2025-12-27 UTC
# Status: Refactored
# Telegram: https://t.me/EasyProTech

"""
Svelte XSS Context

XSS vulnerabilities specific to Svelte applications.
"""

DETAILS = {
    "title": "Svelte XSS",
    "severity": "high",
    "cvss_score": 7.2,
    "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
    "reliability": "high",
    "cwe": ["CWE-79"],
    "owasp": ["A03:2021"],
    "tags": ["svelte", "sveltekit", "framework", "xss", "ssr"],
    "description": """
Svelte XSS can occur through {@html} directive usage, which renders raw HTML.
While Svelte escapes expressions by default, explicit use of @html with user
input leads to XSS. SvelteKit SSR context adds additional attack surfaces.
""",
    "attack_vector": """
SVELTE XSS VECTORS:

1. @HTML DIRECTIVE
   {@html userInput}
   Renders raw HTML without escaping

2. SVELTEKIT LOAD() DATA
   export async function load({ url }) {
     return { html: url.searchParams.get('q') }
   }
   {@html data.html}

3. FORM ACTION DATA
   Form action returns unsanitized HTML

4. API ENDPOINT XSS
   +server.js returns reflected input

5. SSR HTML INJECTION
   Server-rendered content with user input

6. STORES WITH HTML
   const store = writable(userInput)
   {@html $store}

7. SLOT CONTENT INJECTION
   <slot>{@html userHtml}</slot>

8. COMPONENT PROP INJECTION
   <Component html={userInput} />
   {#if html}{@html html}{/if}

9. HYDRATION XSS
   SSR/Client mismatch exploitation
""",
    "remediation": """
SVELTE XSS PREVENTION:

1. AVOID @HTML WITH USER DATA
   Use text binding: {userInput}
   Not: {@html userInput}

2. SANITIZE LOAD() DATA
   import DOMPurify from 'dompurify'
   return { html: DOMPurify.sanitize(input) }

3. VALIDATE FORM ACTIONS
   Check and sanitize all form inputs

4. USE DOMPURIFY
   {@html DOMPurify.sanitize(userHtml)}

5. IMPLEMENT CSP
   Content-Security-Policy header
   In hooks.server.js

6. SANITIZE STORES
   const store = writable(sanitize(input))

7. VALIDATE PROPS
   Type-check component props
   Sanitize before rendering
""",
}

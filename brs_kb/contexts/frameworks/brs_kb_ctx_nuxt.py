#!/usr/bin/env python3
# Project: BRS-KB
# Company: EasyProTech LLC (www.easypro.tech)
# Dev: Brabus
# Date: 2025-12-27 UTC
# Status: Refactored
# Telegram: https://t.me/EasyProTech

"""
Nuxt.js XSS Context

XSS vulnerabilities specific to Nuxt.js applications.
"""

DETAILS = {
    "title": "Nuxt.js XSS",
    "severity": "high",
    "cvss_score": 7.4,
    "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
    "reliability": "high",
    "cwe": ["CWE-79"],
    "owasp": ["A03:2021"],
    "tags": ["nuxt", "vue", "framework", "xss", "ssr"],
    "description": """
Nuxt.js XSS can occur through v-html directive usage, asyncData/fetch data
injection, server middleware reflection, and improper handling of route
parameters in SSR context.
""",
    "attack_vector": """
NUXT.JS XSS VECTORS:

1. V-HTML DIRECTIVE
   <div v-html="userData"></div>
   Renders raw HTML

2. ASYNCDATA INJECTION (Nuxt 2)
   async asyncData({ query }) {
     return { html: query.q }
   }
   <div v-html="html">

3. USEASYNCDATA (Nuxt 3)
   const { data } = await useAsyncData(...)
   <div v-html="data">

4. FETCH() REFLECTION
   Server data reflected to client

5. SERVER MIDDLEWARE
   Parameter reflection in responses

6. ROUTE PARAMETER XSS
   /page/:id where id contains payload

7. HEAD META INJECTION
   useHead({ title: userInput })

8. NUXTSERVERINIT
   Vuex state injection

9. VUEX HYDRATION
   __NUXT__.state manipulation

10. PAYLOAD MANIPULATION
    window.__NUXT__ modification
""",
    "remediation": """
NUXT.JS XSS PREVENTION:

1. AVOID V-HTML
   Use text interpolation: {{ userData }}
   Not: v-html="userData"

2. SANITIZE ASYNCDATA
   import DOMPurify from 'dompurify'
   return { html: DOMPurify.sanitize(data) }

3. VALIDATE ROUTE PARAMS
   Check params in middleware
   Sanitize before use

4. USE TEXTCONTENT
   In client-side code
   ref.value.textContent = input

5. IMPLEMENT CSP
   nuxt.config.js security headers
   Use @nuxt/security module

6. SANITIZE HEAD DATA
   Escape title and meta content

7. VALIDATE STATE
   Check Vuex/Pinia state on hydration
""",
}

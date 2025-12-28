#!/usr/bin/env python3
# Project: BRS-KB
# Company: EasyProTech LLC (www.easypro.tech)
# Dev: Brabus
# Date: 2025-12-27 UTC
# Status: Refactored
# Telegram: https://t.me/EasyProTech

"""
Preact XSS Context

XSS vulnerabilities specific to Preact applications.
"""

DETAILS = {
    "title": "Preact XSS",
    "severity": "high",
    "cvss_score": 7.4,
    "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
    "reliability": "high",
    "cwe": ["CWE-79"],
    "owasp": ["A03:2021"],
    "tags": ["preact", "fresh", "deno", "framework", "xss"],
    "description": """
Preact XSS can occur through dangerouslySetInnerHTML usage, similar to React.
While Preact escapes JSX expressions by default, explicit HTML injection or
improper handling of Fresh/Preact-SSR data leads to XSS.
""",
    "attack_vector": """
PREACT XSS VECTORS:

1. DANGEROUSLYSETINNERHTML
   <div dangerouslySetInnerHTML={{ __html: userInput }} />
   Raw HTML injection

2. FRESH LOADER DATA
   export async function handler(req) {
     return { html: req.url.searchParams.get('q') }
   }

3. FRESH HANDLER REFLECTION
   Response.json({ html: userInput })

4. ROUTE PARAMETER XSS
   /page/:id where id is payload

5. SIGNAL VALUE
   const html = useSignal(userInput)
   <div dangerouslySetInnerHTML={{ __html: html.value }} />

6. PREACT CLI SSR
   Server-rendered with user input

7. ISLAND HYDRATION
   Client hydration with server data

8. REF MANIPULATION
   ref.current.innerHTML = userInput
""",
    "remediation": """
PREACT XSS PREVENTION:

1. AVOID DANGEROUSLYSETINNERHTML
   Use text content: {userInput}
   Not: dangerouslySetInnerHTML

2. SANITIZE LOADER DATA
   import DOMPurify from 'dompurify'
   return { html: DOMPurify.sanitize(input) }

3. VALIDATE ROUTE PARAMS
   Check and sanitize in handler

4. USE DOMPURIFY
   dangerouslySetInnerHTML={{ __html: DOMPurify.sanitize(input) }}

5. IMPLEMENT CSP
   Fresh middleware for headers

6. SANITIZE SIGNALS
   Validate before setting

7. SECURE REFS
   Use textContent not innerHTML
""",
}

#!/usr/bin/env python3
# Project: BRS-KB
# Company: EasyProTech LLC (www.easypro.tech)
# Dev: Brabus
# Date: 2025-12-27 UTC
# Status: Refactored
# Telegram: https://t.me/EasyProTech

"""
Ember.js XSS Context

XSS vulnerabilities specific to Ember.js applications.
"""

DETAILS = {
    "title": "Ember.js XSS",
    "severity": "high",
    "cvss_score": 7.4,
    "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
    "reliability": "high",
    "cwe": ["CWE-79"],
    "owasp": ["A03:2021"],
    "tags": ["ember", "emberjs", "framework", "xss", "handlebars"],
    "description": """
Ember.js XSS can occur through triple-stash {{{...}}} usage which renders
raw HTML, htmlSafe() helper misuse, and component argument injection.
While Ember escapes double-stash expressions, explicit unescaping leads to XSS.
""",
    "attack_vector": """
EMBER.JS XSS VECTORS:

1. TRIPLE-STASH
   {{{userInput}}}
   Renders raw HTML

2. HTMLSAFE()
   htmlSafe(userInput)
   Marks string as safe

3. SAFESTRING
   new SafeString(userInput)
   Creates unescaped string

4. COMPONENT ARGUMENTS
   <Component @html={{userInput}} />
   With triple-stash in component

5. MODEL DATA XSS
   Model attributes rendered unsafely

6. QUERY PARAMETER
   ?q=<script>alert(1)</script>
   Reflected in template

7. EMBER DATA INJECTION
   DS.attr() with HTML content

8. ACTION HANDLER
   {{action userInput}}
   Dynamic action names

9. LINKTO HREF
   <LinkTo @href={{userUrl}}>
   With javascript: protocol
""",
    "remediation": """
EMBER.JS XSS PREVENTION:

1. AVOID TRIPLE-STASH
   Use double-stash: {{userInput}}
   Not: {{{userInput}}}

2. NEVER HTMLSAFE USER DATA
   htmlSafe() only for trusted content
   Sanitize first if needed

3. SANITIZE MODEL DATA
   Clean data before saving
   Validate on display

4. VALIDATE QUERY PARAMS
   Check and sanitize in route

5. IMPLEMENT CSP
   Add CSP headers
   Block inline scripts

6. USE DOMPURIFY
   {{{sanitize userInput}}}
   With sanitize helper

7. SECURE LINKTO
   Validate href values
   Block javascript: URIs
""",
}

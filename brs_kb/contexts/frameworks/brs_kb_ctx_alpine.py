#!/usr/bin/env python3
# Project: BRS-KB
# Company: EasyProTech LLC (www.easypro.tech)
# Dev: Brabus
# Date: 2025-12-27 UTC
# Status: Refactored
# Telegram: https://t.me/EasyProTech

"""
Alpine.js XSS Context

XSS vulnerabilities specific to Alpine.js applications.
"""

DETAILS = {
    "title": "Alpine.js XSS",
    "severity": "high",
    "cvss_score": 7.5,
    "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
    "reliability": "high",
    "cwe": ["CWE-79"],
    "owasp": ["A03:2021"],
    "tags": ["alpine", "alpinejs", "framework", "xss", "lightweight"],
    "description": """
Alpine.js XSS can occur through x-html directive which renders raw HTML,
x-bind with user-controlled attribute values, and Alpine.evaluate() with
user input. Expression evaluation can also be exploited in certain contexts.
""",
    "attack_vector": """
ALPINE.JS XSS VECTORS:

1. X-HTML DIRECTIVE
   <div x-html="userInput"></div>
   Renders raw HTML

2. X-BIND:HREF
   <a x-bind:href="userUrl">
   With javascript: protocol

3. X-ON EXPRESSION
   <button x-on:click="userExpr">
   Expression injection

4. ALPINE.EVALUATE()
   Alpine.evaluate(el, userInput)
   Executes as expression

5. $EL.INNERHTML
   this.$el.innerHTML = userInput

6. X-DATA INJECTION
   <div x-data="{ html: '${userInput}' }">
   Template literal injection

7. X-INIT MALICIOUS
   <div x-init="eval(userInput)">

8. $DISPATCH DATA
   $dispatch('event', userPayload)
   Event data XSS

9. STORE INJECTION
   Alpine.store('name', userInput)
""",
    "remediation": """
ALPINE.JS XSS PREVENTION:

1. AVOID X-HTML
   Use x-text: <div x-text="userInput">
   Not: <div x-html="userInput">

2. VALIDATE X-BIND
   Check URLs before binding
   Block javascript: protocol

3. SANITIZE EVALUATE()
   Never pass user input to Alpine.evaluate()

4. USE CSP
   Block inline script execution
   script-src 'self'

5. ESCAPE X-DATA
   Properly escape user data in x-data
   Use JSON.stringify()

6. VALIDATE EVENTS
   Check $dispatch event data
   Sanitize before use

7. SECURE STORES
   Validate store data on set
""",
}

#!/usr/bin/env python3
# Project: BRS-KB
# Company: EasyProTech LLC (www.easypro.tech)
# Dev: Brabus
# Date: 2025-12-27 UTC
# Status: Refactored
# Telegram: https://t.me/EasyProTech

"""
Lit (LitElement/lit-html) XSS Context

XSS vulnerabilities specific to Lit applications.
"""

DETAILS = {
    "title": "Cross-Site Scripting (XSS) in Lit Framework",
    "severity": "high",
    "cvss_score": 7.2,
    "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
    "reliability": "high",
    "cwe": ["CWE-79"],
    "owasp": ["A03:2021"],
    "tags": ["lit", "lit-html", "litelement", "webcomponents", "xss"],
    "description": """
Lit XSS can occur through unsafeHTML directive usage, which renders raw HTML.
While lit-html escapes expressions by default, explicit use of unsafeHTML or
unsafeSVG with user input leads to XSS. Shadow DOM provides some isolation
but doesn't prevent all attacks.
""",
    "attack_vector": r"""
LIT XSS VECTORS:

1. UNSAFEHTML()
   html\`\${unsafeHTML(userInput)}\`
   Renders raw HTML

2. UNSAFESVG()
   html\`\${unsafeSVG(userSvg)}\`
   Renders raw SVG

3. INNERHTML PROPERTY
   .innerHTML=\${userInput}
   Property binding

4. EVENT LISTENER
   @click=\${userHandler}
   Dynamic event binding

5. ATTRIBUTE BINDING
   href=\${userUrl}
   With javascript: protocol

6. STATIC HTML CONCAT
   html\`<div>\` + userInput + html\`</div>\`
   String concatenation

7. SSR INJECTION
   Server-rendered with user input

8. LIVE DIRECTIVE
   live(userInput) manipulation
""",
    "remediation": r"""
LIT XSS PREVENTION:

1. AVOID UNSAFEHTML
   Use text interpolation: \${userInput}
   Not: \${unsafeHTML(userInput)}

2. SANITIZE BEFORE UNSAFE
   unsafeHTML(DOMPurify.sanitize(input))

3. VALIDATE ATTRIBUTES
   Check href, src values
   Block javascript: protocol

4. USE TEXTCONTENT
   this.textContent = userInput

5. IMPLEMENT CSP
   Add CSP headers
   Block inline scripts

6. VALIDATE EVENTS
   Only allow known handlers

7. SHADOW DOM
   Provides partial isolation
   Not complete protection
""",
}

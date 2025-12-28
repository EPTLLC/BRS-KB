#!/usr/bin/env python3
# Project: BRS-KB
# Company: EasyProTech LLC (www.easypro.tech)
# Dev: Brabus
# Date: 2025-12-27 UTC
# Status: Refactored
# Telegram: https://t.me/EasyProTech

"""
Backbone.js XSS Context

XSS vulnerabilities specific to Backbone.js applications.
"""

DETAILS = {
    "title": "Backbone.js XSS",
    "severity": "high",
    "cvss_score": 7.4,
    "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
    "reliability": "high",
    "cwe": ["CWE-79"],
    "owasp": ["A03:2021"],
    "tags": ["backbone", "backbonejs", "framework", "xss", "underscore"],
    "description": """
Backbone.js XSS can occur through view template injection, model attribute
rendering, and jQuery integration. Backbone relies on external templating
engines, making XSS dependent on the template library used.
""",
    "attack_vector": """
BACKBONE.JS XSS VECTORS:

1. TEMPLATE RENDERING
   this.template({ html: userInput })
   Template with unsanitized data

2. THIS.$EL.HTML()
   this.$el.html(userInput)
   Direct HTML injection

3. MODEL.GET() TO INNERHTML
   el.innerHTML = model.get('field')

4. UNDERSCORE TEMPLATE
   <%= userInput %> (unescaped)
   vs <%- userInput %> (escaped)

5. HANDLEBARS TRIPLE-STASH
   {{{userInput}}}
   In Backbone with Handlebars

6. VIEW EVENT DELEGATION
   events: { 'click': userAction }

7. ROUTER HASH FRAGMENT
   routes: { '*path': 'handle' }
   location.hash injection

8. COLLECTION MODEL
   collection.add({ html: payload })
""",
    "remediation": """
BACKBONE.JS XSS PREVENTION:

1. ESCAPE MODEL ATTRIBUTES
   model.escape('field')
   Instead of model.get('field')

2. SAFE TEMPLATING
   Use <%- %> in Underscore
   Use {{ }} in Handlebars

3. SANITIZE BEFORE HTML()
   this.$el.html(DOMPurify.sanitize(input))

4. VALIDATE ROUTER INPUT
   Check hash/path parameters

5. IMPLEMENT CSP
   Add CSP headers

6. USE TEXT()
   this.$el.text(userInput)
   Instead of html()

7. SANITIZE MODELS
   Clean data before saving
""",
}

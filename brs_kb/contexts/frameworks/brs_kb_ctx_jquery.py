#!/usr/bin/env python3
# Project: BRS-KB
# Company: EasyProTech LLC (www.easypro.tech)
# Dev: Brabus
# Date: 2025-12-27 UTC
# Status: Refactored
# Telegram: https://t.me/EasyProTech

"""
jQuery XSS Context

XSS through jQuery-specific sinks and selector injection.
"""

DETAILS = {
    "title": "jQuery XSS",
    "severity": "high",
    "cvss_score": 7.5,
    "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
    "reliability": "high",
    "cwe": ["CWE-79"],
    "owasp": ["A03:2021"],
    "tags": ["jquery", "javascript", "library", "xss", "dom"],
    "description": """
jQuery XSS exploits jQuery-specific DOM manipulation functions and selector
parsing. Functions like $(), html(), append() can execute scripts when given
attacker-controlled input. Selector injection can also lead to XSS in certain
jQuery versions.
""",
    "attack_vector": """
JQUERY XSS VECTORS:

1. $() ELEMENT CREATION
   $('<img src=x onerror=alert(1)>')
   Creates and executes

2. $.HTML() INJECTION
   $(selector).html(userInput)
   Inserts raw HTML

3. $.APPEND/PREPEND
   $(sel).append(userInput)
   $(sel).prepend(userInput)

4. $.AFTER/BEFORE
   $(sel).after(userInput)
   $(sel).before(userInput)

5. SELECTOR INJECTION (<3.0)
   $(userInput) with HTML
   Creates elements

6. $.GLOBALEVAL()
   $.globalEval(userInput)
   Executes as script

7. $.GETSCRIPT()
   $.getScript(userUrl)
   Loads and executes

8. $.AJAX()
   $.ajax({ url: userUrl })
   URL/data injection

9. $.PARSEHTML()
   $.parseHTML(input, true)
   keepScripts:true

10. $.ON() EVENT
    $(sel).on('click', userHandler)

11. $.LOAD()
    $(sel).load(userUrl)
    Loads HTML from URL
""",
    "remediation": """
JQUERY XSS PREVENTION:

1. UPDATE JQUERY
   Use jQuery 3.5+
   Selector XSS fixed

2. USE $.TEXT()
   $(selector).text(userInput)
   Not: $(selector).html(userInput)

3. SANITIZE BEFORE HTML
   $(sel).html(DOMPurify.sanitize(input))

4. AVOID $() WITH USER INPUT
   Never: $(userInput)
   Use: $(document.getElementById(id))

5. PARSEHTML SAFELY
   $.parseHTML(input, document, false)
   keepScripts: false

6. VALIDATE URLS
   Check before getScript/load/ajax

7. IMPLEMENT CSP
   Block inline script execution
""",
}

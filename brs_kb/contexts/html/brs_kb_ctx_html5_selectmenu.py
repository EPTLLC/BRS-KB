#!/usr/bin/env python3

"""
Project: BRS-KB (BRS XSS Knowledge Base)
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: 2025-12-26 UTC
Status: Created
Telegram: https://t.me/EasyProTech

Knowledge Base: HTML5 Selectmenu API XSS
"""

DETAILS = {
    "title": "Cross-Site Scripting (XSS) via HTML5 Selectmenu API",
    "severity": "medium",
    "cvss_score": 6.5,
    "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:L/A:N",
    "reliability": "medium",
    "cwe": ["CWE-79"],
    "owasp": ["A03:2021"],
    "tags": ["xss", "html5", "selectmenu", "experimental", "chrome-120"],
    "description": """
HTML5 Selectmenu API (Chrome 120+, experimental) provides customizable select elements.
XSS vulnerabilities occur when user input is reflected in selectmenu content or options
without sanitization.

SEVERITY: MEDIUM
Experimental API with limited adoption. Can lead to XSS when selectmenu content is user-controlled.
""",
    "attack_vector": """
SELECTMENU CONTENT INJECTION:
<selectmenu>
  <option><script>alert(1)</script></option>
</selectmenu>

SELECTMENU OPTION INJECTION:
<selectmenu>
  <option value="${userInput}">Option</option>  // XSS if value is rendered
</selectmenu>

SELECTMENU BUTTON INJECTION:
<selectmenu>
  <button><img src=x onerror=alert(1)></button>
</selectmenu>

SELECTMENU LISTBOX INJECTION:
<selectmenu>
  <listbox>
    ${userInput}  // XSS if userInput contains HTML
  </listbox>
</selectmenu>

SELECTMENU OPTION LABEL:
<selectmenu>
  <option><label>${userInput}</label></option>  // XSS
</selectmenu>
""",
    "remediation": """
DEFENSE:

1. Sanitize all selectmenu content
2. Use textContent for option labels
3. Validate option values
4. Implement CSP
5. Use DOMPurify for HTML sanitization

SAFE PATTERN:
const selectmenu = document.createElement('selectmenu');
const option = document.createElement('option');
option.textContent = userInput;  // Safe
selectmenu.appendChild(option);

SANITIZATION:
import DOMPurify from 'dompurify';
option.innerHTML = DOMPurify.sanitize(userInput);

OWASP REFERENCES:
- CWE-79: Cross-site Scripting
- Selectmenu API Specification
""",
}

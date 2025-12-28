#!/usr/bin/env python3

"""
Project: BRS-KB (BRS XSS Knowledge Base)
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: 2025-12-26 UTC
Status: Created
Telegram: https://t.me/EasyProTech

Knowledge Base: Import Assertions XSS
"""

DETAILS = {
    "title": "Cross-Site Scripting (XSS) via Import Assertions",
    "severity": "high",
    "cvss_score": 7.3,
    "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N",
    "reliability": "high",
    "cwe": ["CWE-79", "CWE-829"],
    "owasp": ["A03:2021", "A06:2021"],
    "tags": ["xss", "import-assertions", "import-attributes", "modules", "es2022"],
    "description": """
Import Assertions (ES2022, renamed to Import Attributes) allow specifying import metadata.
XSS vulnerabilities occur when user input controls assertion values or import URLs without
validation.

SEVERITY: HIGH
Can bypass CSP module-src restrictions and lead to arbitrary module loading.
""",
    "attack_vector": """
IMPORT ASSERTION INJECTION:
import data from `${userInput}` assert { type: 'json' };  // XSS if URL is data:

IMPORT ASSERTION TYPE INJECTION:
import data from './data.json' assert { type: userInput };  // XSS if type is 'javascript'

IMPORT ASSERTION WITH EVAL:
const module = await import(`data:text/javascript,${userInput}`, {
  assert: { type: 'javascript' }
});

IMPORT ASSERTION JSON INJECTION:
import data from `${userInput}` assert { type: 'json' };
document.body.innerHTML = data.html;  // XSS if data.html contains HTML

IMPORT ASSERTION CSS INJECTION:
import styles from `${userInput}` assert { type: 'css' };
document.adoptedStyleSheets = [styles];  // XSS if CSS contains @import

DYNAMIC IMPORT WITH ASSERTIONS:
const module = await import(userInput, {
  assert: { type: userInputType }  // XSS if both are controlled
});
""",
    "remediation": """
DEFENSE:

1. Validate all import URLs (whitelist allowed origins)
2. Validate assertion types (whitelist allowed types)
3. Block data: and javascript: URLs
4. Sanitize imported JSON data
5. Implement strict CSP

SAFE PATTERN:
const allowedTypes = ['json', 'css'];
if (!allowedTypes.includes(userInput)) {
  throw new Error('Invalid import type');
}
import data from './data.json' assert { type: userInput };

URL VALIDATION:
function validateImportUrl(url) {
  if (url.startsWith('data:') || url.startsWith('javascript:')) {
    throw new Error('Invalid import URL');
  }
  // Additional validation
  return url;
}

JSON SANITIZATION:
import data from './data.json' assert { type: 'json' };
element.textContent = data.text;  // Safe
// Or
element.innerHTML = DOMPurify.sanitize(data.html);

OWASP REFERENCES:
- CWE-79: Cross-site Scripting
- CWE-829: Inclusion of Functionality from Untrusted Control Sphere
- Import Attributes Specification
""",
}

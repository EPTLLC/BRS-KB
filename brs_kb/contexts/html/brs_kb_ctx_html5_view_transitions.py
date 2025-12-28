#!/usr/bin/env python3

"""
Project: BRS-KB (BRS XSS Knowledge Base)
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: 2025-12-26 UTC
Status: Created
Telegram: https://t.me/EasyProTech

Knowledge Base: View Transitions API XSS
"""

DETAILS = {
    "title": "Cross-Site Scripting (XSS) via View Transitions API",
    "severity": "high",
    "cvss_score": 7.2,
    "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N",
    "reliability": "high",
    "cwe": ["CWE-79"],
    "owasp": ["A03:2021"],
    "tags": ["xss", "view-transitions", "spa", "modern", "chrome-111"],
    "description": """
View Transitions API (Chrome 111+) enables smooth transitions between page states.
XSS vulnerabilities occur when user input is reflected in transition names or content
during document.startViewTransition().

SEVERITY: HIGH
Modern API for SPA transitions. Transition pseudo-elements can contain user content.
""",
    "attack_vector": """
VIEW TRANSITION NAME INJECTION:
document.startViewTransition(() => {
  element.style.viewTransitionName = userInput;  // XSS if reflected
});

VIEW TRANSITION CONTENT:
::view-transition-old(root) {
  content: userInput;  // CSS injection
}

VIEW TRANSITION GROUP:
<div style="view-transition-name: <script>alert(1)</script>">Content</div>

VIEW TRANSITION UPDATE:
document.startViewTransition(() => {
  document.body.innerHTML = userInput;  // XSS
});

VIEW TRANSITION CALLBACK:
document.startViewTransition(() => {
  return new Promise(resolve => {
    div.innerHTML = userInput;  // XSS
    resolve();
  });
});
""",
    "remediation": """
DEFENSE:

1. Sanitize view-transition-name values
2. Validate CSS content in transition pseudo-elements
3. Sanitize content updated during transitions
4. Implement CSP
5. Use safe DOM manipulation methods

SAFE PATTERN:
const sanitizedName = sanitizeViewTransitionName(userInput);
element.style.viewTransitionName = sanitizedName;

CONTENT SANITIZATION:
document.startViewTransition(() => {
  element.textContent = userInput;  // Safe
  // Or
  element.innerHTML = DOMPurify.sanitize(userInput);
});

OWASP REFERENCES:
- CWE-79: Cross-site Scripting
- View Transitions API Specification
""",
}

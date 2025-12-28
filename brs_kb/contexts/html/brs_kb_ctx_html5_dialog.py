#!/usr/bin/env python3

"""
Project: BRS-KB (BRS XSS Knowledge Base)
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: 2025-12-26 UTC
Status: Created
Telegram: https://t.me/EasyProTech

Knowledge Base: HTML5 Dialog Element XSS
"""

DETAILS = {
    "title": "Cross-Site Scripting (XSS) via HTML5 Dialog Element",
    "severity": "high",
    "cvss_score": 7.5,
    "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N",
    "reliability": "high",
    "cwe": ["CWE-79"],
    "owasp": ["A03:2021"],
    "tags": ["xss", "html5", "dialog", "modal", "native"],
    "description": """
HTML5 <dialog> element provides native modal dialogs. XSS occurs when user input is reflected
in dialog content without sanitization. Dialog content is rendered in top layer.

SEVERITY: HIGH
Native dialog implementation with wide browser support. Content rendered in top layer.
""",
    "attack_vector": """
DIALOG CONTENT INJECTION:
<dialog id="modal"><script>alert(1)</script></dialog>
<button onclick="document.getElementById('modal').showModal()">Open</button>

DIALOG WITH EVENT HANDLERS:
<dialog onclose=alert(1)><form method="dialog"><button>Close</button></form></dialog>

DIALOG INNERHTML:
const dialog = document.createElement('dialog');
dialog.innerHTML = userInput;  // XSS
dialog.showModal();

DIALOG OPEN ATTRIBUTE:
<dialog open><img src=x onerror=alert(1)></dialog>

DIALOG RETURNVALUE:
<dialog><form method="dialog"><input name="returnValue" value="<script>alert(1)</script>"></form></dialog>

DIALOG CLOSE EVENT:
dialog.addEventListener('close', () => {
  div.innerHTML = dialog.returnValue;  // XSS if returnValue is user-controlled
});
""",
    "remediation": """
DEFENSE:

1. Sanitize user input before setting dialog content
2. Use textContent for text content
3. Validate dialog returnValue
4. Implement CSP
5. Use DOMPurify for HTML content

SAFE PATTERN:
const dialog = document.createElement('dialog');
dialog.textContent = userInput;  // Safe
// Or
dialog.innerHTML = DOMPurify.sanitize(userInput);

RETURNVALUE VALIDATION:
dialog.addEventListener('close', () => {
  const value = sanitize(dialog.returnValue);
  element.textContent = value;
});

OWASP REFERENCES:
- CWE-79: Cross-site Scripting
- HTML5 Security Cheat Sheet
""",
}

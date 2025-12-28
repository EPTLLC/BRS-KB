#!/usr/bin/env python3

"""
Project: BRS-KB
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: 2025-12-26
Status: Created
Telegram: https://t.me/easyprotech

Knowledge Base: Web Storage XSS
"""

DETAILS = {
    "title": "Cross-Site Scripting (XSS) via Web Storage",
    "severity": "high",
    "cvss_score": 7.5,
    "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N",
    "reliability": "certain",
    "cwe": ["CWE-79", "CWE-922"],
    "owasp": ["A03:2021"],
    "tags": ["xss", "localstorage", "sessionstorage", "storage", "persistent", "dom"],
    "description": """
Web Storage XSS (Stored DOM XSS) occurs when data stored in localStorage or sessionStorage
is read and rendered without sanitization. Creates persistent XSS that survives page reloads.

SEVERITY: HIGH
Persistent XSS that doesn't require server-side storage. Difficult to detect and remove.
Affects all pages on the same origin that read the poisoned storage.
""",
    "attack_vector": """
LOCALSTORAGE INJECTION:
localStorage.setItem('user', '<img src=x onerror=alert(1)>');
// Later: div.innerHTML = localStorage.getItem('user');

SESSIONSTORAGE XSS:
sessionStorage.setItem('msg', '<script>alert(1)</script>');

JSON PARSE + RENDER:
localStorage.setItem('config', '{"html":"<img src=x onerror=alert(1)>"}');
div.innerHTML = JSON.parse(localStorage.getItem('config')).html;

POSTMESSAGE TO STORAGE:
window.onmessage = e => localStorage.setItem('data', e.data);

URL HASH TO STORAGE:
localStorage.setItem('lastHash', location.hash);
div.innerHTML = localStorage.getItem('lastHash');

STORAGE EVENT LISTENER:
window.onstorage = e => div.innerHTML = e.newValue;

PROTOTYPE POLLUTION VIA STORAGE:
localStorage.setItem('__proto__', '{"innerHTML":"<script>alert(1)</script>"}');

ARRAY STORAGE:
const items = JSON.parse(localStorage.getItem('items')) || [];
items.forEach(i => list.innerHTML += `<li>${i}</li>`);

INDEXEDDB + RENDER:
db.get('userData').then(data => div.innerHTML = data.bio);
""",
    "remediation": """
DEFENSE:

1. SANITIZE data BEFORE storing
2. SANITIZE data AFTER reading, before DOM insertion
3. Use textContent, not innerHTML
4. Validate JSON schema after parsing
5. Don't store HTML in storage
6. Clear storage on logout
7. Implement CSP

SAFE PATTERN:
// Store
localStorage.setItem('user', DOMPurify.sanitize(userInput));

// Retrieve
element.textContent = localStorage.getItem('user');

// JSON
const config = JSON.parse(localStorage.getItem('config'));
Object.keys(config).forEach(key => {
  element.textContent = config[key];  // Safe
});

SANITIZATION LIBRARY:
const clean = DOMPurify.sanitize(localStorage.getItem('data'));

OWASP REFERENCES:
- CWE-79: Cross-site Scripting
- CWE-922: Insecure Storage
- HTML5 Security Cheat Sheet
""",
}

#!/usr/bin/env python3

"""
Project: BRS-KB (BRS XSS Knowledge Base)
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: 2025-12-26 UTC
Status: Created
Telegram: https://t.me/EasyProTech

Knowledge Base: Web Locks API XSS
"""

DETAILS = {
    "title": "Cross-Site Scripting (XSS) via Web Locks API",
    "severity": "medium",
    "cvss_score": 6.2,
    "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:L/A:N",
    "reliability": "medium",
    "cwe": ["CWE-79"],
    "owasp": ["A03:2021"],
    "tags": ["xss", "web-locks", "synchronization", "concurrency", "chrome-69"],
    "description": """
Web Locks API (Chrome 69+) provides synchronization primitives. XSS vulnerabilities occur
when user input controls lock names or lock callback execution without validation.

SEVERITY: MEDIUM
Can lead to race conditions and XSS if lock names or callbacks are user-controlled.
""",
    "attack_vector": """
WEB LOCKS NAME INJECTION:
await navigator.locks.request(userInput, async (lock) => {
  // XSS if lock name is controlled
});

WEB LOCKS CALLBACK INJECTION:
await navigator.locks.request('lock', async (lock) => {
  eval(userInput);  // XSS if callback contains user input
});

WEB LOCKS WITH INNERHTML:
await navigator.locks.request('lock', async (lock) => {
  element.innerHTML = userInput;  // XSS
});

WEB LOCKS SHARED STATE:
let sharedState = {};
await navigator.locks.request('lock', async (lock) => {
  sharedState.data = userInput;  // XSS if sharedState is rendered
});

WEB LOCKS POSTMESSAGE:
await navigator.locks.request('lock', async (lock) => {
  window.postMessage(userInput, '*');  // XSS if message is rendered
});
""",
    "remediation": """
DEFENSE:

1. Validate lock names (alphanumeric only)
2. Sanitize data stored in lock callbacks
3. Use textContent instead of innerHTML
4. Validate shared state before rendering
5. Implement input validation

SAFE PATTERN:
function validateLockName(name) {
  if (!/^[a-z0-9-]+$/i.test(name)) {
    throw new Error('Invalid lock name');
  }
  return name;
}
await navigator.locks.request(validateLockName(userInput), async (lock) => {
  // Safe operations
});

DATA SANITIZATION:
await navigator.locks.request('lock', async (lock) => {
  element.textContent = userInput;  // Safe
  // Or
  element.innerHTML = DOMPurify.sanitize(userInput);
});

OWASP REFERENCES:
- CWE-79: Cross-site Scripting
- Web Locks API Specification
""",
}

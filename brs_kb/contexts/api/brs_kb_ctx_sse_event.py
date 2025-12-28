#!/usr/bin/env python3

"""
Project: BRS-KB
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: 2025-12-26
Status: Created
Telegram: https://t.me/easyprotech

Knowledge Base: SSE Event Type XSS
"""

DETAILS = {
    "title": "Cross-Site Scripting (XSS) via SSE Event Type",
    "severity": "medium",
    "cvss_score": 6.5,
    "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:L/A:N",
    "reliability": "certain",
    "cwe": ["CWE-79"],
    "owasp": ["A03:2021"],
    "tags": ["xss", "sse", "eventsource", "event", "type"],
    "description": """
SSE event type XSS occurs when the event: field value is reflected or used
in DOM manipulation. Custom event types can contain malicious content.

SEVERITY: MEDIUM
Event types are less commonly exploited but can be reflected in logs or debug output.
Dynamic event listener registration can be abused.
""",
    "attack_vector": """
EVENT TYPE REFLECTION:
event: <script>alert(1)</script>
data: test
// If event type shown in debug/log

DYNAMIC LISTENER:
event: notification
// Code: source.addEventListener(eventType, handler);
// If eventType is attacker-controlled

EVENT TYPE IN DOM:
source.addEventListener('message', (e) => {
  log.innerHTML += `Event: ${e.type}<br>`;
});

WILDCARD LISTENER:
// Listening to all events including malicious types
source.onmessage = (e) => {
  // e.type could be manipulated
};

CUSTOM EVENT DISPATCH:
event: customEvent
data: <payload>
// document.dispatchEvent(new CustomEvent(e.type, {detail: e.data}));

LOG INJECTION:
event: </td><script>alert(1)</script><td>
data: test
""",
    "remediation": """
DEFENSE:

1. VALIDATE event types against allowlist
2. Don't reflect event types in DOM
3. Use predefined event names
4. Sanitize before logging
5. Implement CSP

SAFE PATTERN:
const ALLOWED_EVENTS = ['notification', 'update', 'ping'];

const source = new EventSource('/events');
ALLOWED_EVENTS.forEach(event => {
  source.addEventListener(event, (e) => {
    // Handle known event types only
    handleEvent(event, e.data);
  });
});

EVENT VALIDATION:
function isValidEventType(type) {
  return /^[a-zA-Z][a-zA-Z0-9_-]*$/.test(type);
}

SAFE LOGGING:
console.log('Event:', event.type.replace(/[<>]/g, ''));

OWASP REFERENCES:
- CWE-79: Cross-site Scripting
""",
}

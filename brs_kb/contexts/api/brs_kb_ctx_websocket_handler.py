#!/usr/bin/env python3

"""
Project: BRS-KB
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: 2025-12-26
Status: Created
Telegram: https://t.me/easyprotech

Knowledge Base: WebSocket Handler XSS
"""

DETAILS = {
    "title": "Cross-Site Scripting (XSS) via WebSocket Event Handlers",
    "severity": "high",
    "cvss_score": 7.5,
    "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N",
    "reliability": "certain",
    "cwe": ["CWE-79"],
    "owasp": ["A03:2021"],
    "tags": ["xss", "websocket", "handler", "event", "onopen", "onclose"],
    "description": """
WebSocket event handler XSS occurs when onopen, onclose, onerror, or custom event
handlers process data that gets rendered without sanitization.

SEVERITY: HIGH
Event handlers are often overlooked for security. Custom events can contain malicious data.
Framework-specific handlers (Socket.IO events) are common vectors.
""",
    "attack_vector": """
ONERROR HANDLER:
ws.onerror = (e) => {
  errorDiv.innerHTML = `Error: ${e.message}`;
};

ONCLOSE REASON:
ws.onclose = (e) => {
  div.innerHTML = `Closed: ${e.reason}`;
};
// Server sends: reason = "<script>alert(1)</script>"

CUSTOM EVENT HANDLER:
socket.on('notification', (data) => {
  $('#notify').html(data.message);  // XSS
});

ONOPEN DATA:
ws.onopen = () => {
  ws.send(location.hash);  // Hash may contain XSS for reflection
};

DYNAMIC HANDLER:
const handler = userInput;
socket.on(handler, callback);  // Event name injection

MULTIPLE HANDLERS:
socket.on('*', (event, data) => {
  log.innerHTML += `${event}: ${data}`;  // Both can contain XSS
});

RECONNECTION HANDLER:
socket.on('reconnect_attempt', (n) => {
  status.innerHTML = `Attempt ${n}`;
});
// If n is manipulated
""",
    "remediation": """
DEFENSE:

1. SANITIZE all event data before DOM insertion
2. Use textContent for safe display
3. Validate event types
4. Don't reflect error details
5. Use typed event handlers
6. Implement CSP

SAFE HANDLERS:
ws.onerror = () => {
  errorDiv.textContent = 'Connection error';
};

ws.onclose = (e) => {
  const reason = e.reason || 'Unknown';
  div.textContent = `Closed: ${reason.slice(0, 100)}`;
};

socket.on('notification', (data) => {
  const p = document.createElement('p');
  p.textContent = data.message;
  notify.appendChild(p);
});

TYPED EVENTS:
interface NotificationEvent {
  message: string;
  type: 'info' | 'warning' | 'error';
}
socket.on('notification', (data: NotificationEvent) => {
  // TypeScript validation
});

OWASP REFERENCES:
- CWE-79: Cross-site Scripting
- WebSocket Security
""",
}

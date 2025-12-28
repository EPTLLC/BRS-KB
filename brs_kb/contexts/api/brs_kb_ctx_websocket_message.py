#!/usr/bin/env python3

"""
Project: BRS-KB
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: 2025-12-26
Status: Created
Telegram: https://t.me/easyprotech

Knowledge Base: WebSocket Message XSS
"""

DETAILS = {
    "title": "Cross-Site Scripting (XSS) via WebSocket Messages",
    "severity": "high",
    "cvss_score": 7.5,
    "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N",
    "reliability": "certain",
    "cwe": ["CWE-79"],
    "owasp": ["A03:2021"],
    "tags": ["xss", "websocket", "realtime", "chat", "message", "socket.io"],
    "description": """
WebSocket message XSS occurs when data received via WebSocket is rendered in the DOM
without sanitization. Common in chat apps, live feeds, and real-time dashboards.

SEVERITY: HIGH
WebSocket messages bypass traditional request/response validation.
Data is often trusted because it comes from the server.
""",
    "attack_vector": """
ONMESSAGE HANDLER:
ws.onmessage = (e) => {
  div.innerHTML = e.data;  // XSS!
};
// Message: <script>alert(1)</script>

JSON MESSAGE:
ws.onmessage = (e) => {
  const msg = JSON.parse(e.data);
  chat.innerHTML += `<p>${msg.text}</p>`;  // XSS!
};

SOCKET.IO:
socket.on('message', (data) => {
  $('#messages').append(`<li>${data.text}</li>`);
});

BINARY MESSAGE:
ws.binaryType = 'blob';
ws.onmessage = (e) => {
  // Blob converted to text and rendered
};

BROADCAST MESSAGE:
// Attacker sends XSS to all connected clients
socket.emit('broadcast', '<img src=x onerror=alert(1)>');

NOTIFICATION:
ws.onmessage = (e) => {
  new Notification(e.data);  // Can contain XSS if shown in DOM
};

RECONNECT MESSAGE:
// XSS in reconnection data
socket.on('reconnect', () => {
  div.innerHTML = socket.data;
});
""",
    "remediation": """
DEFENSE:

1. SANITIZE all WebSocket message data
2. Use textContent, not innerHTML
3. Validate message format/schema
4. Authenticate WebSocket connections
5. Rate limit messages
6. Implement CSP

SAFE PATTERN:
ws.onmessage = (event) => {
  const data = JSON.parse(event.data);
  const p = document.createElement('p');
  p.textContent = data.text;  // Safe
  chat.appendChild(p);
};

// With sanitization:
ws.onmessage = (event) => {
  const clean = DOMPurify.sanitize(event.data);
  div.innerHTML = clean;
};

SOCKET.IO SAFE:
socket.on('message', (data) => {
  const li = document.createElement('li');
  li.textContent = data.text;
  document.getElementById('messages').appendChild(li);
});

OWASP REFERENCES:
- CWE-79: Cross-site Scripting
- WebSocket Security Best Practices
""",
}

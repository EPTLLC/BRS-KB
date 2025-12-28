#!/usr/bin/env python3

"""
Project: BRS-KB
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: 2025-12-26
Status: Created
Telegram: https://t.me/easyprotech

Knowledge Base: WebSocket URL XSS
"""

DETAILS = {
    "title": "Cross-Site Scripting (XSS) via WebSocket URL",
    "severity": "high",
    "cvss_score": 7.2,
    "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N",
    "reliability": "certain",
    "cwe": ["CWE-79", "CWE-601"],
    "owasp": ["A03:2021"],
    "tags": ["xss", "websocket", "url", "wss", "connection", "redirect"],
    "description": """
WebSocket URL XSS occurs when user input controls the WebSocket connection URL
or when WebSocket endpoint URLs are reflected in the page.

SEVERITY: HIGH
Attacker can redirect WebSocket to malicious server. URL parameters may contain XSS.
Connection errors often reflect the URL in error messages.
""",
    "attack_vector": """
USER-CONTROLLED WS URL:
const ws = new WebSocket(userInput);
// userInput: wss://evil.com/ws

URL PARAMETER XSS:
const ws = new WebSocket(`wss://example.com/ws?user=${userInput}`);
// userInput: <script>alert(1)</script>
// Server error reflects URL

PATH INJECTION:
const ws = new WebSocket(`wss://example.com/${userInput}/ws`);
// userInput: ../../<script>alert(1)</script>

PROTOCOL CONFUSION:
new WebSocket('javascript:alert(1)');  // May throw, but error shown

ERROR DISPLAY:
ws.onerror = (e) => {
  div.innerHTML = `Error connecting to ${ws.url}`;  // XSS in URL
};

REDIRECT VIA WS:
// Server sends redirect URL via WebSocket
ws.onmessage = (e) => {
  location.href = e.data;  // Open redirect
};

WS QUERY STRING:
wss://example.com/ws?callback=<script>alert(1)</script>
""",
    "remediation": """
DEFENSE:

1. HARDCODE WebSocket URLs
2. Validate URL format strictly
3. Use allowlist for WebSocket hosts
4. Don't reflect URL in error messages
5. Validate origin on server
6. Use secure WebSocket (wss://)

SAFE PATTERN:
// Hardcoded URL
const WS_URL = 'wss://example.com/ws';
const ws = new WebSocket(WS_URL);

// If dynamic, validate:
function getWsUrl(room) {
  const safeRoom = encodeURIComponent(room.replace(/[^a-z0-9]/gi, ''));
  return `wss://example.com/ws/${safeRoom}`;
}

ERROR HANDLING:
ws.onerror = () => {
  div.textContent = 'Connection error';  // Generic, safe
};

SERVER VALIDATION:
// Validate Origin header
if (request.headers.origin !== 'https://example.com') {
  socket.close();
}

OWASP REFERENCES:
- CWE-79: Cross-site Scripting
- CWE-601: Open Redirect
""",
}

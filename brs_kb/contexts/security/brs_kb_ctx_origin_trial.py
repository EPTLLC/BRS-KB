#!/usr/bin/env python3

"""
Project: BRS-KB (BRS XSS Knowledge Base)
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: 2025-12-27 UTC
Status: Created
Telegram: https://t.me/EasyProTech

Origin Trial Features XSS Context - Main Module
"""

from .brs_kb_ctx_origin_trial_data import ATTACK_VECTOR, DESCRIPTION, REMEDIATION


DETAILS = {
    "title": "Cross-Site Scripting (XSS) in Origin Trial Features",
    "severity": "medium",
    "cvss_score": 6.5,
    "cvss_vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:L/A:N",
    "reliability": "tentative",
    "cwe": ["CWE-79"],
    "owasp": ["A03:2021"],
    "tags": ["xss", "origin-trial", "experimental", "security", "modern-web", "2024"],
    "description": DESCRIPTION,
    "attack_vector": ATTACK_VECTOR,
    "remediation": REMEDIATION,
}

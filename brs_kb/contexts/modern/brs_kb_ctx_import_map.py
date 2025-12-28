#!/usr/bin/env python3

"""
Project: BRS-KB (BRS XSS Knowledge Base)
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: 2025-12-27 UTC
Status: Created
Telegram: https://t.me/EasyProTech

Import Maps XSS Context - Main Module
"""

from .brs_kb_ctx_import_map_data import ATTACK_VECTOR, DESCRIPTION, REMEDIATION


DETAILS = {
    "title": "Cross-Site Scripting (XSS) in Import Maps",
    "severity": "critical",
    "cvss_score": 8.8,
    "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H",
    "reliability": "certain",
    "cwe": ["CWE-79", "CWE-915"],
    "owasp": ["A03:2021"],
    "tags": [
        "xss",
        "import-map",
        "module",
        "json-injection",
        "prototype-pollution",
        "modern-web",
        "2024",
    ],
    "description": DESCRIPTION,
    "attack_vector": ATTACK_VECTOR,
    "remediation": REMEDIATION,
}

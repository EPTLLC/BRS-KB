#!/usr/bin/env python3

"""
Project: BRS-KB (BRS XSS Knowledge Base)
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: 2025-12-04 19:21:27 UTC
Status: Refactored
Telegram: https://t.me/easyprotech

Knowledge Base: DOM-based Cross-Site Scripting (XSS) - Main Module
Refactored to comply with 250-300 lines per file rule
"""

from .brs_kb_ctx_dom_xss_data import DESCRIPTION, REMEDIATION
from .brs_kb_ctx_dom_xss_vectors import ATTACK_VECTOR


DETAILS = {
    "title": "DOM-based Cross-Site Scripting (XSS)",
    # Metadata for SIEM/Triage Integration
    "severity": "high",
    "cvss_score": 7.4,
    "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:L/A:N",
    "reliability": "certain",
    "cwe": ["CWE-79"],
    "owasp": ["A03:2021"],
    "tags": ["xss", "dom", "client-side", "reflected", "dom-manipulation"],
    "description": DESCRIPTION,
    "attack_vector": ATTACK_VECTOR,
    "remediation": REMEDIATION,
}

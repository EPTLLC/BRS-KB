#!/usr/bin/env python3

"""
Project: BRS-KB (BRS XSS Knowledge Base)
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: 2025-10-25 12:00:00 UTC
Status: Refactored
Telegram: https://t.me/easyprotech

Knowledge Base: JavaScript Context - Main Module
Refactored to comply with 250-300 lines per file rule
"""

from .brs_kb_ctx_javascript_data import DESCRIPTION, REMEDIATION
from .brs_kb_ctx_javascript_vectors import ATTACK_VECTOR


DETAILS = {
    "title": "Cross-Site Scripting (XSS) in JavaScript Context",
    # Metadata for SIEM/Triage Integration
    "severity": "critical",
    "cvss_score": 9.0,
    "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H",
    "reliability": "certain",
    "cwe": ["CWE-79"],
    "owasp": ["A03:2021"],
    "tags": ["xss", "javascript", "code-injection", "critical", "direct-execution"],
    "description": DESCRIPTION,
    "attack_vector": ATTACK_VECTOR,
    "remediation": REMEDIATION,
}

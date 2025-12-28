#!/usr/bin/env python3

"""
Project: BRS-KB (BRS XSS Knowledge Base)
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: 2025-12-04 19:21:27 UTC
Status: Refactored
Telegram: https://t.me/easyprotech

Knowledge Base: iframe Sandbox XSS Context - Main Module
Refactored to comply with 250-300 lines per file rule
"""

from .brs_kb_ctx_iframe_sandbox_data import DESCRIPTION, REMEDIATION
from .brs_kb_ctx_iframe_sandbox_vectors import ATTACK_VECTOR


DETAILS = {
    "title": "Cross-Site Scripting (XSS) in iframe Sandbox Context",
    # Metadata for SIEM/Triage Integration
    "severity": "medium",
    "cvss_score": 6.3,
    "cvss_vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:L/A:N",
    "reliability": "certain",
    "cwe": ["CWE-79"],
    "owasp": ["A03:2021"],
    "tags": ["xss", "iframe", "sandbox", "isolation", "modern-web"],
    "description": DESCRIPTION,
    "attack_vector": ATTACK_VECTOR,
    "remediation": REMEDIATION,
}

#!/usr/bin/env python3

"""
Project: BRS-KB (BRS XSS Knowledge Base)
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: 2025-12-04 19:21:27 UTC
Status: Refactored
Telegram: https://t.me/easyprotech

Knowledge Base: Cross-Site Scripting (XSS) in Service Worker - Main Module
Refactored to comply with 250-300 lines per file rule
"""

from .brs_kb_ctx_service_worker_data import DESCRIPTION, REMEDIATION
from .brs_kb_ctx_service_worker_vectors import ATTACK_VECTOR


DETAILS = {
    "title": "Cross-Site Scripting (XSS) in Service Worker",
    # Metadata for SIEM/Triage Integration
    "severity": "high",
    "cvss_score": 7.8,
    "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N",
    "reliability": "certain",
    "cwe": ["CWE-79"],
    "owasp": ["A03:2021"],
    "tags": ["xss", "service-worker", "pwa", "offline", "modern-web"],
    "description": DESCRIPTION,
    "attack_vector": ATTACK_VECTOR,
    "remediation": REMEDIATION,
}

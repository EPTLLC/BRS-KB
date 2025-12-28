#!/usr/bin/env python3

"""
Project: BRS-KB (BRS XSS Knowledge Base)
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: 2025-10-25 12:00:00 UTC
Status: Refactored
Telegram: https://t.me/easyprotech

Knowledge Base: GraphQL XSS Context - Main Module
Refactored to comply with 250-300 lines per file rule
"""

from .brs_kb_ctx_graphql_data import DESCRIPTION, REMEDIATION
from .brs_kb_ctx_graphql_vectors import ATTACK_VECTOR


DETAILS = {
    "title": "Cross-Site Scripting (XSS) in GraphQL Context",
    # Metadata for SIEM/Triage Integration
    "severity": "high",
    "cvss_score": 7.4,
    "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N",
    "reliability": "certain",
    "cwe": ["CWE-79"],
    "owasp": ["A03:2021"],
    "tags": ["xss", "graphql", "api-injection", "query-manipulation", "modern-web"],
    "description": DESCRIPTION,
    "attack_vector": ATTACK_VECTOR,
    "remediation": REMEDIATION,
}

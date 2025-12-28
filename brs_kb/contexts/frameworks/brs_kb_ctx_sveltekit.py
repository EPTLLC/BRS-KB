#!/usr/bin/env python3

"""
Project: BRS-KB (BRS XSS Knowledge Base)
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: 2025-12-27 UTC
Status: Created
Telegram: https://t.me/EasyProTech

SvelteKit Specific XSS Context - Main Module
"""

from .brs_kb_ctx_sveltekit_data import ATTACK_VECTOR, DESCRIPTION, REMEDIATION


DETAILS = {
    "title": "Cross-Site Scripting (XSS) in SvelteKit",
    "severity": "high",
    "cvss_score": 7.5,
    "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N",
    "reliability": "certain",
    "cwe": ["CWE-79"],
    "owasp": ["A03:2021"],
    "tags": ["xss", "sveltekit", "framework", "svelte", "modern-web", "2024"],
    "description": DESCRIPTION,
    "attack_vector": ATTACK_VECTOR,
    "remediation": REMEDIATION,
}

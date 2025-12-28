#!/usr/bin/env python3
"""
Project: BRS-KB (BRS XSS Knowledge Base)
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: 2025-12-27 UTC
Status: Active
Telegram: https://t.me/EasyProTech

External sources package - payloads from community and security researchers.
Proper attribution included in each file.
"""

from .brs_kb_0xsobky import SOBKY_PAYLOADS
from .brs_kb_blind_callback import BLIND_CALLBACK_PAYLOADS
from .brs_kb_community_misc import COMMUNITY_MISC_PAYLOADS
from .brs_kb_exotic_techniques import EXOTIC_TECHNIQUES_PAYLOADS
from .brs_kb_hakluke_weaponised import HAKLUKE_WEAPONISED_PAYLOADS
from .brs_kb_payloadbox import PAYLOADBOX_XSS
from .brs_kb_payloadsallthethings import PAYLOADSALLTHETHINGS_XSS
from .brs_kb_seclists import SECLISTS_XSS_PAYLOADS
from .brs_kb_terjanq_tiny import TERJANQ_TINY_PAYLOADS


# Combined external sources database
EXTERNAL_SOURCES_DATABASE = {
    **SOBKY_PAYLOADS,
    **BLIND_CALLBACK_PAYLOADS,
    **COMMUNITY_MISC_PAYLOADS,
    **EXOTIC_TECHNIQUES_PAYLOADS,
    **HAKLUKE_WEAPONISED_PAYLOADS,
    **PAYLOADBOX_XSS,
    **PAYLOADSALLTHETHINGS_XSS,
    **SECLISTS_XSS_PAYLOADS,
    **TERJANQ_TINY_PAYLOADS,
}

EXTERNAL_SOURCES_TOTAL = len(EXTERNAL_SOURCES_DATABASE)

__all__ = [
    "BLIND_CALLBACK_PAYLOADS",
    "COMMUNITY_MISC_PAYLOADS",
    "EXOTIC_TECHNIQUES_PAYLOADS",
    "EXTERNAL_SOURCES_DATABASE",
    "EXTERNAL_SOURCES_TOTAL",
    "HAKLUKE_WEAPONISED_PAYLOADS",
    "PAYLOADBOX_XSS",
    "PAYLOADSALLTHETHINGS_XSS",
    "SECLISTS_XSS_PAYLOADS",
    "SOBKY_PAYLOADS",
    "TERJANQ_TINY_PAYLOADS",
]

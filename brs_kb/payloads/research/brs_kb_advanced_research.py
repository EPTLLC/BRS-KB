#!/usr/bin/env python3
"""
Project: BRS-KB (BRS XSS Knowledge Base)
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: 2025-12-27 UTC
Status: Refactored
Telegram: https://t.me/EasyProTech

Ultra Deep XSS Payloads

The deepest knowledge - obscure browser behaviors, forgotten APIs,
race conditions, timing attacks, and techniques from ancient scrolls.

Refactored into 4 parts for better maintainability.
"""

from .brs_kb_advanced_research_part1 import BRS_KB_ULTRA_DEEP_PAYLOADS_PART1
from .brs_kb_advanced_research_part2 import BRS_KB_ULTRA_DEEP_PAYLOADS_PART2
from .brs_kb_advanced_research_part3 import BRS_KB_ULTRA_DEEP_PAYLOADS_PART3
from .brs_kb_advanced_research_part4 import BRS_KB_ULTRA_DEEP_PAYLOADS_PART4


BRS_KB_ULTRA_DEEP_PAYLOADS = {
    **BRS_KB_ULTRA_DEEP_PAYLOADS_PART1,
    **BRS_KB_ULTRA_DEEP_PAYLOADS_PART2,
    **BRS_KB_ULTRA_DEEP_PAYLOADS_PART3,
    **BRS_KB_ULTRA_DEEP_PAYLOADS_PART4,
}

BRS_KB_ULTRA_DEEP_TOTAL_PAYLOADS = len(BRS_KB_ULTRA_DEEP_PAYLOADS)

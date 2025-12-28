#!/usr/bin/env python3
"""
Project: BRS-KB (BRS XSS Knowledge Base)
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: 2025-12-27 UTC
Status: Refactored
Telegram: https://t.me/EasyProTech

Deep Memory XSS Payloads

Payloads from deep knowledge - obscure techniques, rare edge cases,
historical exploits, and forgotten bypasses that still work.

Refactored into 4 parts for better maintainability.
"""

from .brs_kb_deep_part1 import BRS_KB_DEEP_MEMORY_PAYLOADS_PART1
from .brs_kb_deep_part2 import BRS_KB_DEEP_MEMORY_PAYLOADS_PART2
from .brs_kb_deep_part3 import BRS_KB_DEEP_MEMORY_PAYLOADS_PART3
from .brs_kb_deep_part4 import BRS_KB_DEEP_MEMORY_PAYLOADS_PART4


BRS_KB_DEEP_MEMORY_PAYLOADS = {
    **BRS_KB_DEEP_MEMORY_PAYLOADS_PART1,
    **BRS_KB_DEEP_MEMORY_PAYLOADS_PART2,
    **BRS_KB_DEEP_MEMORY_PAYLOADS_PART3,
    **BRS_KB_DEEP_MEMORY_PAYLOADS_PART4,
}

BRS_KB_DEEP_MEMORY_TOTAL_PAYLOADS = len(BRS_KB_DEEP_MEMORY_PAYLOADS)

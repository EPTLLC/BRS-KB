#!/usr/bin/env python3
"""
Project: BRS-KB (BRS XSS Knowledge Base)
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: 2025-12-27 UTC
Status: Refactored
Telegram: https://t.me/EasyProTech

Absolute Final XSS Payloads

The TRULY final extraction - techniques I almost forgot,
research papers, academic exploits, browser-specific quirks,
and the most obscure corners of my knowledge.

Refactored into 4 parts for better maintainability.
"""

from .brs_kb_extra_part1 import BRS_KB_ABSOLUTE_FINAL_PAYLOADS_PART1
from .brs_kb_extra_part2 import BRS_KB_ABSOLUTE_FINAL_PAYLOADS_PART2
from .brs_kb_extra_part3 import BRS_KB_ABSOLUTE_FINAL_PAYLOADS_PART3
from .brs_kb_extra_part4 import BRS_KB_ABSOLUTE_FINAL_PAYLOADS_PART4


BRS_KB_ABSOLUTE_FINAL_PAYLOADS = {
    **BRS_KB_ABSOLUTE_FINAL_PAYLOADS_PART1,
    **BRS_KB_ABSOLUTE_FINAL_PAYLOADS_PART2,
    **BRS_KB_ABSOLUTE_FINAL_PAYLOADS_PART3,
    **BRS_KB_ABSOLUTE_FINAL_PAYLOADS_PART4,
}

BRS_KB_ABSOLUTE_FINAL_TOTAL_PAYLOADS = len(BRS_KB_ABSOLUTE_FINAL_PAYLOADS)

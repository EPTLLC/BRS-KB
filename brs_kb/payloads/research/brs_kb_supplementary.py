#!/usr/bin/env python3
"""
Project: BRS-KB (BRS XSS Knowledge Base)
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: 2025-12-27 UTC
Status: Refactored
Telegram: https://t.me/EasyProTech

Truly Last XSS Payloads

This is genuinely the final extraction.
The deepest corners, the forgotten techniques, the research notes.

Refactored into 3 parts for better maintainability.
"""

from .brs_kb_supplementary_part1 import BRS_KB_TRULY_LAST_PAYLOADS_PART1
from .brs_kb_supplementary_part2 import BRS_KB_TRULY_LAST_PAYLOADS_PART2
from .brs_kb_supplementary_part3 import BRS_KB_TRULY_LAST_PAYLOADS_PART3


BRS_KB_TRULY_LAST_PAYLOADS = {
    **BRS_KB_TRULY_LAST_PAYLOADS_PART1,
    **BRS_KB_TRULY_LAST_PAYLOADS_PART2,
    **BRS_KB_TRULY_LAST_PAYLOADS_PART3,
}

BRS_KB_TRULY_LAST_TOTAL_PAYLOADS = len(BRS_KB_TRULY_LAST_PAYLOADS)

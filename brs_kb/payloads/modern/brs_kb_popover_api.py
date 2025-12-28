#!/usr/bin/env python3
"""
Project: BRS-KB (BRS XSS Knowledge Base)
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: 2025-12-27 UTC
Status: Refactored
Telegram: https://t.me/EasyProTech

Popover API XSS Payloads

Popover API allows creating popover elements without JavaScript.
Can be used for XSS via toggle and beforetoggle events.

Refactored into 2 parts for better maintainability.
"""

from .brs_kb_popover_api_part1 import POPOVER_API_PAYLOADS_PART1
from .brs_kb_popover_api_part2 import POPOVER_API_PAYLOADS_PART2


POPOVER_API_PAYLOADS = {
    **POPOVER_API_PAYLOADS_PART1,
    **POPOVER_API_PAYLOADS_PART2,
}

POPOVER_API_TOTAL_PAYLOADS = len(POPOVER_API_PAYLOADS)

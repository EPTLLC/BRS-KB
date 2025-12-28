#!/usr/bin/env python3
"""
Project: BRS-KB (BRS XSS Knowledge Base)
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: 2025-12-27 UTC
Status: Refactored
Telegram: https://t.me/EasyProTech

Modern Browser Payloads

Refactored into 3 parts for better maintainability.
"""

from .brs_kb_extended_modern_part1 import MODERN_BROWSER_PAYLOADS_PART1
from .brs_kb_extended_modern_part2 import MODERN_BROWSER_PAYLOADS_PART2
from .brs_kb_extended_modern_part3 import MODERN_BROWSER_PAYLOADS_PART3


MODERN_BROWSER_PAYLOADS = {
    **MODERN_BROWSER_PAYLOADS_PART1,
    **MODERN_BROWSER_PAYLOADS_PART2,
    **MODERN_BROWSER_PAYLOADS_PART3,
}

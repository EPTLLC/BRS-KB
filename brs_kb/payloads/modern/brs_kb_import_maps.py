#!/usr/bin/env python3
"""
Project: BRS-KB (BRS XSS Knowledge Base)
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: 2025-12-27 UTC
Status: Refactored
Telegram: https://t.me/EasyProTech

Import Maps XSS Payloads

Import Maps allow controlling module imports.
Can be used for XSS via data URLs and javascript: protocol.

Refactored into 2 parts for better maintainability.
"""

from .brs_kb_import_maps_part1 import IMPORT_MAPS_PAYLOADS_PART1
from .brs_kb_import_maps_part2 import IMPORT_MAPS_PAYLOADS_PART2


IMPORT_MAPS_PAYLOADS = {
    **IMPORT_MAPS_PAYLOADS_PART1,
    **IMPORT_MAPS_PAYLOADS_PART2,
}

IMPORT_MAPS_TOTAL_PAYLOADS = len(IMPORT_MAPS_PAYLOADS)

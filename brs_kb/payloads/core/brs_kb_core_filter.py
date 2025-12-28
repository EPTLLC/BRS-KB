#!/usr/bin/env python3
"""
Project: BRS-KB (BRS XSS Knowledge Base)
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: 2025-12-27 UTC
Status: Refactored - Aggregator
Telegram: https://t.me/EasyProTech

Filter Evasion Core Payloads - Aggregator
Combines all filter evasion core payloads from sub-modules.
"""

from typing import Dict

from ..models import PayloadEntry
from .brs_kb_core_filter_part1 import FILTER_EVASION_CORE_PAYLOADS_PART1
from .brs_kb_core_filter_part2 import FILTER_EVASION_CORE_PAYLOADS_PART2
from .brs_kb_core_filter_part3 import FILTER_EVASION_CORE_PAYLOADS_PART3


FILTER_EVASION_CORE_PAYLOADS: Dict[str, PayloadEntry] = {
    **FILTER_EVASION_CORE_PAYLOADS_PART1,
    **FILTER_EVASION_CORE_PAYLOADS_PART2,
    **FILTER_EVASION_CORE_PAYLOADS_PART3,
}

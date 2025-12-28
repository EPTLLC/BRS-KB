#!/usr/bin/env python3
"""
Project: BRS-KB (BRS XSS Knowledge Base)
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: 2025-12-27 UTC
Status: Refactored - Aggregator
Telegram: https://t.me/EasyProTech

Advanced Core Payloads - Aggregator
Combines all advanced core payloads from sub-modules.
"""

from typing import Dict

from ..models import PayloadEntry
from .brs_kb_core_advanced_part1 import ADVANCED_CORE_PAYLOADS_PART1
from .brs_kb_core_advanced_part2 import ADVANCED_CORE_PAYLOADS_PART2
from .brs_kb_core_advanced_part3 import ADVANCED_CORE_PAYLOADS_PART3


ADVANCED_CORE_PAYLOADS: Dict[str, PayloadEntry] = {
    **ADVANCED_CORE_PAYLOADS_PART1,
    **ADVANCED_CORE_PAYLOADS_PART2,
    **ADVANCED_CORE_PAYLOADS_PART3,
}

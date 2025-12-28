#!/usr/bin/env python3
"""
Project: BRS-KB (BRS XSS Knowledge Base)
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: 2025-12-27 UTC
Status: Refactored - Aggregator
Telegram: https://t.me/EasyProTech

Framework Specific Core Payloads - Aggregator
Combines all framework specific core payloads from sub-modules.
"""

from typing import Dict

from ..models import PayloadEntry
from .brs_kb_core_framework_part1 import FRAMEWORK_SPECIFIC_CORE_PAYLOADS_PART1
from .brs_kb_core_framework_part2 import FRAMEWORK_SPECIFIC_CORE_PAYLOADS_PART2
from .brs_kb_core_framework_part3 import FRAMEWORK_SPECIFIC_CORE_PAYLOADS_PART3


FRAMEWORK_SPECIFIC_CORE_PAYLOADS: Dict[str, PayloadEntry] = {
    **FRAMEWORK_SPECIFIC_CORE_PAYLOADS_PART1,
    **FRAMEWORK_SPECIFIC_CORE_PAYLOADS_PART2,
    **FRAMEWORK_SPECIFIC_CORE_PAYLOADS_PART3,
}

#!/usr/bin/env python3
"""
Project: BRS-KB (BRS XSS Knowledge Base)
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: 2025-12-27 UTC
Status: Refactored - Aggregator
Telegram: https://t.me/EasyProTech

Basic Core Payloads - Aggregator
Combines all basic core payloads from sub-modules.
"""

from typing import Dict

from ..models import PayloadEntry
from .brs_kb_core_basic_part1 import BASIC_CORE_PAYLOADS_PART1
from .brs_kb_core_basic_part2 import BASIC_CORE_PAYLOADS_PART2


BASIC_CORE_PAYLOADS: Dict[str, PayloadEntry] = {
    **BASIC_CORE_PAYLOADS_PART1,
    **BASIC_CORE_PAYLOADS_PART2,
}

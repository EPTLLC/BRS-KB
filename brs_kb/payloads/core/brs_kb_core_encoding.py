#!/usr/bin/env python3
"""
Project: BRS-KB (BRS XSS Knowledge Base)
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: 2025-12-27 UTC
Status: Refactored - Aggregator
Telegram: https://t.me/EasyProTech

Encoding Core Payloads - Aggregator
Combines all encoding core payloads from sub-modules.
"""

from typing import Dict

from ..models import PayloadEntry
from .brs_kb_core_encoding_part1 import ENCODING_CORE_PAYLOADS_PART1
from .brs_kb_core_encoding_part2 import ENCODING_CORE_PAYLOADS_PART2


ENCODING_CORE_PAYLOADS: Dict[str, PayloadEntry] = {
    **ENCODING_CORE_PAYLOADS_PART1,
    **ENCODING_CORE_PAYLOADS_PART2,
}

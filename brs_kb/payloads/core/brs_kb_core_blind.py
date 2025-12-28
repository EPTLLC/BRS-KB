#!/usr/bin/env python3
"""
Project: BRS-KB (BRS XSS Knowledge Base)
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: 2025-12-27 UTC
Status: Refactored - Aggregator
Telegram: https://t.me/EasyProTech

Blind Payloads - Aggregator
Combines all blind payloads from sub-modules.
"""

from typing import Dict

from ..models import PayloadEntry
from .brs_kb_blind_part1 import BLIND_XSS_CORE_PAYLOADS_PART1
from .brs_kb_blind_part2 import BLIND_XSS_CORE_PAYLOADS_PART2


BLIND_XSS_CORE_PAYLOADS: Dict[str, PayloadEntry] = {
    **BLIND_XSS_CORE_PAYLOADS_PART1,
    **BLIND_XSS_CORE_PAYLOADS_PART2,
}

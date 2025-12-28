#!/usr/bin/env python3
"""
Project: BRS-KB (BRS XSS Knowledge Base)
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: 2025-12-27 UTC
Status: Refactored - Aggregator
Telegram: https://t.me/EasyProTech

Context Specific Core Payloads - Aggregator
Combines all context specific core payloads from sub-modules.
"""

from typing import Dict

from ..models import PayloadEntry
from .brs_kb_core_context_part1 import CONTEXT_SPECIFIC_CORE_PAYLOADS_PART1
from .brs_kb_core_context_part2 import CONTEXT_SPECIFIC_CORE_PAYLOADS_PART2
from .brs_kb_core_context_part3 import CONTEXT_SPECIFIC_CORE_PAYLOADS_PART3


CONTEXT_SPECIFIC_CORE_PAYLOADS: Dict[str, PayloadEntry] = {
    **CONTEXT_SPECIFIC_CORE_PAYLOADS_PART1,
    **CONTEXT_SPECIFIC_CORE_PAYLOADS_PART2,
    **CONTEXT_SPECIFIC_CORE_PAYLOADS_PART3,
}

#!/usr/bin/env python3
"""
Project: BRS-KB (BRS XSS Knowledge Base)
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: 2025-12-27 UTC
Status: Refactored - Aggregator
Telegram: https://t.me/EasyProTech

Dom Core Payloads - Aggregator
Combines all dom core payloads from sub-modules.
"""

from typing import Dict

from ..models import PayloadEntry
from .brs_kb_core_dom_part1 import DOM_XSS_CORE_PAYLOADS_PART1
from .brs_kb_core_dom_part2 import DOM_XSS_CORE_PAYLOADS_PART2


DOM_XSS_CORE_PAYLOADS: Dict[str, PayloadEntry] = {
    **DOM_XSS_CORE_PAYLOADS_PART1,
    **DOM_XSS_CORE_PAYLOADS_PART2,
}

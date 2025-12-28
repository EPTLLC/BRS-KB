#!/usr/bin/env python3
"""
Project: BRS-KB (BRS XSS Knowledge Base)
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: 2025-12-27 UTC
Status: Refactored - Aggregator
Telegram: https://t.me/EasyProTech

WAF Bypass Core Payloads - Aggregator
Combines all WAF bypass core payloads from sub-modules.
"""

from typing import Dict

from ..models import PayloadEntry
from .brs_kb_core_waf_part1 import WAF_BYPASS_CORE_PAYLOADS_PART1
from .brs_kb_core_waf_part2 import WAF_BYPASS_CORE_PAYLOADS_PART2
from .brs_kb_core_waf_part3 import WAF_BYPASS_CORE_PAYLOADS_PART3


WAF_BYPASS_CORE_PAYLOADS: Dict[str, PayloadEntry] = {
    **WAF_BYPASS_CORE_PAYLOADS_PART1,
    **WAF_BYPASS_CORE_PAYLOADS_PART2,
    **WAF_BYPASS_CORE_PAYLOADS_PART3,
}

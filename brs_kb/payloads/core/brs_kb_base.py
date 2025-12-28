#!/usr/bin/env python3
"""
Project: BRS-KB (BRS XSS Knowledge Base)
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: 2025-12-27 UTC
Status: Refactored - Aggregator
Telegram: https://t.me/EasyProTech

Base Payload Database - Aggregator
Combines all base payloads from sub-modules.
"""

from typing import Dict

from ..models import PayloadEntry
from .brs_kb_base_advanced import ADVANCED_BASE_PAYLOADS
from .brs_kb_base_comprehensive_part1 import COMPREHENSIVE_BASE_PAYLOADS_PART1
from .brs_kb_base_comprehensive_part2 import COMPREHENSIVE_BASE_PAYLOADS_PART2
from .brs_kb_base_context import CONTEXT_BASE_PAYLOADS
from .brs_kb_base_html import HTML_BASE_PAYLOADS
from .brs_kb_base_modern_part1 import MODERN_BASE_PAYLOADS_PART1
from .brs_kb_base_modern_part2 import MODERN_BASE_PAYLOADS_PART2


PAYLOAD_DATABASE: Dict[str, PayloadEntry] = {
    **HTML_BASE_PAYLOADS,
    **CONTEXT_BASE_PAYLOADS,
    **ADVANCED_BASE_PAYLOADS,
    **MODERN_BASE_PAYLOADS_PART1,
    **MODERN_BASE_PAYLOADS_PART2,
    **COMPREHENSIVE_BASE_PAYLOADS_PART1,
    **COMPREHENSIVE_BASE_PAYLOADS_PART2,
}

TOTAL_PAYLOADS = len(PAYLOAD_DATABASE)
CONTEXTS_COVERED = set()
for payload in PAYLOAD_DATABASE.values():
    CONTEXTS_COVERED.update(payload.contexts)

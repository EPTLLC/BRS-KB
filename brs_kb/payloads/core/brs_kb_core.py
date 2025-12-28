#!/usr/bin/env python3
"""
Project: BRS-KB
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: 2025-12-27 UTC
Status: Refactored - Aggregator
Telegram: https://t.me/EasyProTech

Core XSS Payloads - Aggregator
Combines all core payloads from sub-modules.
"""

from typing import Dict

from ..models import PayloadEntry
from .brs_kb_core_advanced import ADVANCED_CORE_PAYLOADS
from .brs_kb_core_basic import BASIC_CORE_PAYLOADS
from .brs_kb_core_blind import BLIND_XSS_CORE_PAYLOADS
from .brs_kb_core_context import CONTEXT_SPECIFIC_CORE_PAYLOADS
from .brs_kb_core_dom import DOM_XSS_CORE_PAYLOADS
from .brs_kb_core_encoding import ENCODING_CORE_PAYLOADS
from .brs_kb_core_filter import FILTER_EVASION_CORE_PAYLOADS
from .brs_kb_core_framework import FRAMEWORK_SPECIFIC_CORE_PAYLOADS
from .brs_kb_core_polyglot import POLYGLOT_CORE_PAYLOADS
from .brs_kb_core_waf import WAF_BYPASS_CORE_PAYLOADS


CORE_PAYLOAD_DATABASE: Dict[str, PayloadEntry] = {
    **ADVANCED_CORE_PAYLOADS,
    **BASIC_CORE_PAYLOADS,
    **BLIND_XSS_CORE_PAYLOADS,
    **CONTEXT_SPECIFIC_CORE_PAYLOADS,
    **DOM_XSS_CORE_PAYLOADS,
    **ENCODING_CORE_PAYLOADS,
    **FILTER_EVASION_CORE_PAYLOADS,
    **FRAMEWORK_SPECIFIC_CORE_PAYLOADS,
    **POLYGLOT_CORE_PAYLOADS,
    **WAF_BYPASS_CORE_PAYLOADS,
}

CORE_TOTAL_PAYLOADS = len(CORE_PAYLOAD_DATABASE)

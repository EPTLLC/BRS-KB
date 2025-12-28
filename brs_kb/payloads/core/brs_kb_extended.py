#!/usr/bin/env python3
"""
Project: BRS-KB (BRS XSS Knowledge Base)
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: 2025-12-27 UTC
Status: Refactored - Aggregator
Telegram: https://t.me/EasyProTech

Extended Payload Database - Aggregator
Combines all extended payloads from sub-modules.
"""

from typing import Dict

from ..models import PayloadEntry
from .brs_kb_extended_exotic import EXOTIC_PAYLOADS
from .brs_kb_extended_graphql import GRAPHQL_PAYLOADS
from .brs_kb_extended_modern import MODERN_BROWSER_PAYLOADS
from .brs_kb_extended_sse import SSE_PAYLOADS
from .brs_kb_extended_waf import WAF_BYPASS_2024_PAYLOADS
from .brs_kb_extended_websocket import WEBSOCKET_PAYLOADS


EXTENDED_PAYLOAD_DATABASE: Dict[str, PayloadEntry] = {
    **MODERN_BROWSER_PAYLOADS,
    **WAF_BYPASS_2024_PAYLOADS,
    **WEBSOCKET_PAYLOADS,
    **GRAPHQL_PAYLOADS,
    **SSE_PAYLOADS,
    **EXOTIC_PAYLOADS,
}

EXTENDED_TOTAL_PAYLOADS = len(EXTENDED_PAYLOAD_DATABASE)
EXTENDED_CATEGORIES = [
    "modern_browser",
    "waf_bypass_2024",
    "websocket",
    "graphql",
    "sse",
    "exotic",
]

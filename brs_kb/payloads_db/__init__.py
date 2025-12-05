#!/usr/bin/env python3

"""
Project: BRS-KB (BRS XSS Knowledge Base)
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: 2025-12-04 12:00:00 UTC
Status: Created
Telegram: https://t.me/easyprotech

Payload database package
Main entry point for payload database functionality
"""

from .models import PayloadEntry
from .data import PAYLOAD_DATABASE, PAYLOAD_DB_VERSION, TOTAL_PAYLOADS, CONTEXTS_COVERED
from .queries import (
    get_payload_by_id,
    get_payloads_by_context,
    get_payloads_by_severity,
    get_payloads_by_tag,
    get_waf_bypass_payloads,
)
from .search import search_payloads
from .operations import get_all_payloads, add_payload, export_payloads
from .info import get_database_info
from .testing import test_payload_effectiveness

# Export all functions and data
__all__ = [
    "PayloadEntry",
    "PAYLOAD_DATABASE",
    "get_payload_by_id",
    "get_payloads_by_context",
    "get_payloads_by_severity",
    "get_payloads_by_tag",
    "get_waf_bypass_payloads",
    "get_database_info",
    "search_payloads",
    "test_payload_effectiveness",
    "get_all_payloads",
    "add_payload",
    "export_payloads",
    "PAYLOAD_DB_VERSION",
    "TOTAL_PAYLOADS",
    "CONTEXTS_COVERED",
]



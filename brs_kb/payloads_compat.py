#!/usr/bin/env python3

"""
Project: BRS-KB (BRS XSS Knowledge Base)
Company: EasyProTech LLC (www.easyprotech)
Dev: Brabus
Date: Sat 25 Oct 2025 12:00:00 UTC
Status: Refactored
Telegram: https://t.me/easyprotech

Payload Database: Backward compatibility wrapper
This file maintains backward compatibility while the actual implementation
has been moved to brs_kb/payloads/ package
"""

# Import from refactored package for backward compatibility
from brs_kb.payloads import (
    CONTEXTS_COVERED,
    PAYLOAD_DATABASE,
    PAYLOAD_DB_VERSION,
    TOTAL_PAYLOADS,
    PayloadEntry,
    add_payload,
    export_payloads,
    get_all_payloads,
    get_database_info,
    get_payload_by_id,
    get_payloads_by_context,
    get_payloads_by_severity,
    get_payloads_by_tag,
    get_waf_bypass_payloads,
    search_payloads,
    test_payload_effectiveness,
)


# Export all for backward compatibility
__all__ = [
    "CONTEXTS_COVERED",
    "PAYLOAD_DATABASE",
    "PAYLOAD_DB_VERSION",
    "TOTAL_PAYLOADS",
    "PayloadEntry",
    "add_payload",
    "export_payloads",
    "get_all_payloads",
    "get_database_info",
    "get_payload_by_id",
    "get_payloads_by_context",
    "get_payloads_by_severity",
    "get_payloads_by_tag",
    "get_waf_bypass_payloads",
    "search_payloads",
    "test_payload_effectiveness",
]

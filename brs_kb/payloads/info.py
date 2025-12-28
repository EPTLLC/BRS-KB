#!/usr/bin/env python3

"""
Project: BRS-KB (BRS XSS Knowledge Base)
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: 2025-12-04 12:00:00 UTC
Status: Created
Telegram: https://t.me/easyprotech

Payload database information functions
Provides database statistics and metadata
"""

from typing import Any, Dict, Set

from brs_kb.version import __version__


def get_database_info() -> Dict[str, Any]:
    """Get database information from in-memory payload database."""
    # Import here to avoid circular imports
    from . import FULL_PAYLOAD_DATABASE

    # Calculate contexts covered
    contexts_covered: Set[str] = set()
    severities: Set[str] = set()
    tags: Set[str] = set()
    browsers: Set[str] = set()
    waf_bypass_count = 0

    for payload in FULL_PAYLOAD_DATABASE.values():
        contexts_covered.update(payload.contexts)
        severities.add(payload.severity)
        tags.update(payload.tags)
        browsers.update(payload.browser_support)
        if payload.waf_evasion:
            waf_bypass_count += 1

    return {
        "version": __version__,
        "total_payloads": len(FULL_PAYLOAD_DATABASE),
        "contexts_covered": sorted(contexts_covered),
        "severities": sorted(severities),
        "waf_bypass_count": waf_bypass_count,
        "tags": sorted(tags),
        "browser_support": sorted(browsers),
        "database_type": "in-memory",
    }

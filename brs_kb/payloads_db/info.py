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

from typing import Dict, Any
from .data import PAYLOAD_DATABASE, PAYLOAD_DB_VERSION, TOTAL_PAYLOADS, CONTEXTS_COVERED
from .queries import get_waf_bypass_payloads


def get_database_info() -> Dict[str, Any]:
    """Get database information (tries SQLite first, falls back to in-memory)"""
    # Try SQLite database first
    try:
        from brs_kb.payloads_db_sqlite import get_database
        db = get_database()
        stats = db.get_stats()
        return {
            **stats,
            "database_type": "sqlite",
            "database_path": db.db_path,
        }
    except (ImportError, Exception):
        # Fallback to in-memory database
        pass
    
    # Original in-memory implementation
    return {
        "version": PAYLOAD_DB_VERSION,
        "total_payloads": TOTAL_PAYLOADS,
        "contexts_covered": sorted(list(CONTEXTS_COVERED)),
        "severities": list(set(p.severity for p in PAYLOAD_DATABASE.values())),
        "waf_bypass_count": len(get_waf_bypass_payloads()),
        "tags": list(set(tag for p in PAYLOAD_DATABASE.values() for tag in p.tags)),
        "browser_support": list(
            set(browser for p in PAYLOAD_DATABASE.values() for browser in p.browser_support)
        ),
    }



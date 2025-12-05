#!/usr/bin/env python3

"""
Project: BRS-KB (BRS XSS Knowledge Base)
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: 2025-12-04 12:00:00 UTC
Status: Created
Telegram: https://t.me/easyprotech

Payload database query functions
Provides functions for querying payloads by various criteria
"""

from typing import List, Optional
from .models import PayloadEntry
from .data import PAYLOAD_DATABASE


def get_payload_by_id(payload_id: str) -> Optional[PayloadEntry]:
    """Get payload by ID"""
    return PAYLOAD_DATABASE.get(payload_id)


def get_payloads_by_context(context: str) -> List[PayloadEntry]:
    """Get all payloads effective in a specific context (tries SQLite first, falls back to in-memory)"""
    # Try SQLite database first
    try:
        from brs_kb.payloads_db_sqlite import get_database
        db = get_database()
        return db.get_payloads_by_context(context)
    except (ImportError, Exception):
        # Fallback to in-memory database
        pass
    
    # Original in-memory implementation
    return [payload for payload in PAYLOAD_DATABASE.values() if context in payload.contexts]


def get_payloads_by_severity(severity: str) -> List[PayloadEntry]:
    """Get all payloads by severity level (tries SQLite first, falls back to in-memory)"""
    # Try SQLite database first
    try:
        from brs_kb.payloads_db_sqlite import get_database
        db = get_database()
        return db.get_payloads_by_severity(severity)
    except (ImportError, Exception):
        # Fallback to in-memory database
        pass
    
    # Original in-memory implementation
    return [payload for payload in PAYLOAD_DATABASE.values() if payload.severity == severity]


def get_payloads_by_tag(tag: str) -> List[PayloadEntry]:
    """Get all payloads by tag (tries SQLite first, falls back to in-memory)"""
    # Try SQLite database first
    try:
        from brs_kb.payloads_db_sqlite import get_database
        db = get_database()
        return db.get_payloads_by_tag(tag)
    except (ImportError, Exception):
        # Fallback to in-memory database
        pass
    
    # Original in-memory implementation
    return [payload for payload in PAYLOAD_DATABASE.values() if tag in payload.tags]


def get_waf_bypass_payloads() -> List[PayloadEntry]:
    """Get payloads designed for WAF bypass (tries SQLite first, falls back to in-memory)"""
    # Try SQLite database first
    try:
        from brs_kb.payloads_db_sqlite import get_database
        db = get_database()
        return db.get_waf_bypass_payloads()
    except (ImportError, Exception):
        # Fallback to in-memory database
        pass
    
    # Original in-memory implementation
    return [payload for payload in PAYLOAD_DATABASE.values() if payload.waf_evasion]



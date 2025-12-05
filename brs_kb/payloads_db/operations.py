#!/usr/bin/env python3

"""
Project: BRS-KB (BRS XSS Knowledge Base)
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: 2025-12-04 12:00:00 UTC
Status: Created
Telegram: https://t.me/easyprotech

Payload database operations
Provides functions for adding, exporting and managing payloads
"""

import json
from typing import Dict, List, Tuple
from .models import PayloadEntry
from .data import PAYLOAD_DATABASE


def get_all_payloads() -> Dict[str, PayloadEntry]:
    """Get all payloads in database (tries SQLite first, falls back to in-memory)"""
    # Try SQLite database first
    try:
        from brs_kb.payloads_db_sqlite import get_database
        db = get_database()
        entries = db.get_all_payloads()
        # Convert to dict format for compatibility
        return {entry.payload[:50]: entry for entry in entries}
    except (ImportError, Exception):
        # Fallback to in-memory database
        pass
    
    # Original in-memory implementation
    return PAYLOAD_DATABASE.copy()


def add_payload(payload_entry: PayloadEntry) -> bool:
    """Add new payload to database"""
    if payload_entry.payload in [p.payload for p in PAYLOAD_DATABASE.values()]:
        return False  # Duplicate payload

    # Generate ID from payload (simplified)
    payload_id = (
        payload_entry.payload.replace("<", "")
        .replace(">", "")
        .replace('"', "")
        .replace("'", "")[:50]
    )
    payload_id = payload_id.replace(" ", "_").replace("(", "").replace(")", "").replace(";", "")

    PAYLOAD_DATABASE[payload_id] = payload_entry

    # Rebuild index after adding payload
    try:
        from brs_kb.payload_index import rebuild_index
        rebuild_index()
    except ImportError:
        pass  # Index not available

    return True


def export_payloads(format: str = "json") -> str:
    """Export payloads in specified format"""
    if format == "json":
        return json.dumps(
            {
                payload_id: {
                    "payload": payload.payload,
                    "contexts": payload.contexts,
                    "severity": payload.severity,
                    "cvss_score": payload.cvss_score,
                    "description": payload.description,
                    "tags": payload.tags,
                }
                for payload_id, payload in PAYLOAD_DATABASE.items()
            },
            indent=2,
        )

    return "Unsupported format"



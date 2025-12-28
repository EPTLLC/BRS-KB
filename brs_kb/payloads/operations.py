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
from typing import Dict

from .models import PayloadEntry


def _get_full_database():
    """Get the full payload database (lazy import to avoid circular imports)."""
    from . import FULL_PAYLOAD_DATABASE

    return FULL_PAYLOAD_DATABASE


def get_all_payloads() -> Dict[str, PayloadEntry]:
    """Get all payloads in database."""
    return _get_full_database().copy()


def add_payload(payload_entry: PayloadEntry) -> bool:
    """Add new payload to database."""
    db = _get_full_database()

    if payload_entry.payload in [p.payload for p in db.values()]:
        return False  # Duplicate payload

    # Generate ID from payload (simplified)
    payload_id = (
        payload_entry.payload.replace("<", "")
        .replace(">", "")
        .replace('"', "")
        .replace("'", "")[:50]
    )
    payload_id = payload_id.replace(" ", "_").replace("(", "").replace(")", "").replace(";", "")

    db[payload_id] = payload_entry

    # Rebuild index after adding payload
    try:
        from brs_kb.payload_index import rebuild_index

        rebuild_index()
    except ImportError:
        pass  # Index not available

    return True


def export_payloads(format: str = "json") -> str:
    """Export payloads in specified format."""
    db = _get_full_database()

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
                for payload_id, payload in db.items()
            },
            indent=2,
        )

    return "Unsupported format"

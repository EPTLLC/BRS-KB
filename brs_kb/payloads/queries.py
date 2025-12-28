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


def _get_full_database():
    """Get the full payload database (lazy import to avoid circular imports)."""
    from . import FULL_PAYLOAD_DATABASE

    return FULL_PAYLOAD_DATABASE


def get_payload_by_id(payload_id: str) -> Optional[PayloadEntry]:
    """Get payload by ID."""
    return _get_full_database().get(payload_id)


def get_payloads_by_context(context: str) -> List[PayloadEntry]:
    """Get all payloads effective in a specific context."""
    return [payload for payload in _get_full_database().values() if context in payload.contexts]


def get_payloads_by_severity(severity: str) -> List[PayloadEntry]:
    """Get all payloads by severity level."""
    return [payload for payload in _get_full_database().values() if payload.severity == severity]


def get_payloads_by_tag(tag: str) -> List[PayloadEntry]:
    """Get all payloads by tag."""
    return [payload for payload in _get_full_database().values() if tag in payload.tags]


def get_waf_bypass_payloads() -> List[PayloadEntry]:
    """Get payloads designed for WAF bypass."""
    return [payload for payload in _get_full_database().values() if payload.waf_evasion]

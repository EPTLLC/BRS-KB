#!/usr/bin/env python3

"""
Project: BRS-KB (BRS XSS Knowledge Base)
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: 2025-12-04 12:00:00 UTC
Status: Created
Telegram: https://t.me/easyprotech

Payload testing functions
Provides functions for testing payload effectiveness
"""

from typing import Any, Dict

from .queries import get_payload_by_id


def test_payload_effectiveness(payload_id: str, test_context: str) -> Dict[str, Any]:
    """Test payload effectiveness in a specific context"""
    payload = get_payload_by_id(payload_id)
    if not payload:
        return {"error": "Payload not found"}

    is_effective = test_context in payload.contexts
    confidence = 1.0 if is_effective else 0.0

    return {
        "payload_id": payload_id,
        "payload": payload.payload,
        "context": test_context,
        "is_effective": is_effective,
        "confidence": confidence,
        "severity": payload.severity,
        "cvss_score": payload.cvss_score,
        "tags": payload.tags,
        "waf_evasion": payload.waf_evasion,
    }

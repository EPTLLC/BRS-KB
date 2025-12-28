#!/usr/bin/env python3
"""
Project: BRS-KB (BRS XSS Knowledge Base)
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: 2025-12-27 UTC
Status: Active
Telegram: https://t.me/EasyProTech

Attack Vectors Payloads Package
"""

from .brs_kb_attributes import ATTRIBUTE_INJECTION_PAYLOADS, ATTRIBUTE_INJECTION_TOTAL
from .brs_kb_css_advanced import CSS_ADVANCED_PAYLOADS, CSS_ADVANCED_TOTAL


__all__ = [
    "ATTRIBUTE_INJECTION_PAYLOADS",
    "ATTRIBUTE_INJECTION_TOTAL",
    "CSS_ADVANCED_PAYLOADS",
    "CSS_ADVANCED_TOTAL",
]

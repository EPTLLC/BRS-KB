#!/usr/bin/env python3
"""
Project: BRS-KB (BRS XSS Knowledge Base)
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: 2025-12-27 UTC
Status: Active
Telegram: https://t.me/EasyProTech

Browser APIs Payloads Package
"""

from .brs_kb_modern_apis import MODERN_BROWSER_APIS_PAYLOADS, MODERN_BROWSER_APIS_TOTAL
from .brs_kb_storage_apis import STORAGE_APIS_PAYLOADS, STORAGE_APIS_TOTAL


__all__ = [
    "MODERN_BROWSER_APIS_PAYLOADS",
    "MODERN_BROWSER_APIS_TOTAL",
    "STORAGE_APIS_PAYLOADS",
    "STORAGE_APIS_TOTAL",
]

#!/usr/bin/env python3
"""
Project: BRS-KB (BRS XSS Knowledge Base)
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: 2025-12-27 UTC
Status: Created
Telegram: https://t.me/EasyProTech

Modern Web APIs Payloads Package
"""

from .brs_kb_dialog_api import DIALOG_API_PAYLOADS, DIALOG_API_TOTAL_PAYLOADS
from .brs_kb_import_maps import IMPORT_MAPS_PAYLOADS, IMPORT_MAPS_TOTAL_PAYLOADS
from .brs_kb_popover_api import POPOVER_API_PAYLOADS, POPOVER_API_TOTAL_PAYLOADS
from .brs_kb_view_transitions import (
    VIEW_TRANSITIONS_API_PAYLOADS,
    VIEW_TRANSITIONS_API_TOTAL_PAYLOADS,
)


MODERN_API_PAYLOADS = {
    **VIEW_TRANSITIONS_API_PAYLOADS,
    **POPOVER_API_PAYLOADS,
    **DIALOG_API_PAYLOADS,
    **IMPORT_MAPS_PAYLOADS,
}

MODERN_API_TOTAL_PAYLOADS = len(MODERN_API_PAYLOADS)

#!/usr/bin/env python3
"""
Project: BRS-KB (BRS XSS Knowledge Base)
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: 2025-12-27 UTC
Status: Created
Telegram: https://t.me/EasyProTech

Modern Web APIs Contexts Package
"""

from .brs_kb_ctx_anchor_positioning import DETAILS as ANCHOR_POSITIONING_DETAILS
from .brs_kb_ctx_container_queries import DETAILS as CONTAINER_QUERIES_DETAILS
from .brs_kb_ctx_css_nesting import DETAILS as CSS_NESTING_DETAILS
from .brs_kb_ctx_dialog import DETAILS as DIALOG_DETAILS
from .brs_kb_ctx_import_map import DETAILS as IMPORT_MAP_DETAILS
from .brs_kb_ctx_popover import DETAILS as POPOVER_DETAILS
from .brs_kb_ctx_shared_worker import DETAILS as SHARED_WORKER_DETAILS
from .brs_kb_ctx_speculation_rules import DETAILS as SPECULATION_RULES_DETAILS
from .brs_kb_ctx_view_transitions import DETAILS as VIEW_TRANSITIONS_DETAILS
from .brs_kb_ctx_web_locks import DETAILS as WEB_LOCKS_DETAILS
from .brs_kb_ctx_web_manifest import DETAILS as WEB_MANIFEST_DETAILS
from .brs_kb_ctx_web_share_target import DETAILS as WEB_SHARE_TARGET_DETAILS


MODERN_CONTEXTS = {
    "view-transitions-api": VIEW_TRANSITIONS_DETAILS,
    "popover-api": POPOVER_DETAILS,
    "dialog-api": DIALOG_DETAILS,
    "import-map": IMPORT_MAP_DETAILS,
    "speculation-rules": SPECULATION_RULES_DETAILS,
    "shared-worker": SHARED_WORKER_DETAILS,
    "web-locks": WEB_LOCKS_DETAILS,
    "web-share-target": WEB_SHARE_TARGET_DETAILS,
    "web-manifest": WEB_MANIFEST_DETAILS,
    "anchor-positioning": ANCHOR_POSITIONING_DETAILS,
    "container-queries": CONTAINER_QUERIES_DETAILS,
    "css-nesting": CSS_NESTING_DETAILS,
}

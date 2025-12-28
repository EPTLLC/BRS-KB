#!/usr/bin/env python3
"""
Project: BRS-KB (BRS XSS Knowledge Base)
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: 2025-12-27 UTC
Status: Created
Telegram: https://t.me/EasyProTech

Security Bypasses Contexts Package
"""

from .brs_kb_ctx_cross_origin_isolated import DETAILS as CROSS_ORIGIN_ISOLATED_DETAILS
from .brs_kb_ctx_csp_strict_dynamic import DETAILS as CSP_STRICT_DYNAMIC_DETAILS
from .brs_kb_ctx_origin_trial import DETAILS as ORIGIN_TRIAL_DETAILS
from .brs_kb_ctx_sanitizer_api import DETAILS as SANITIZER_API_DETAILS
from .brs_kb_ctx_shared_array_buffer import DETAILS as SHARED_ARRAY_BUFFER_DETAILS
from .brs_kb_ctx_trusted_types import DETAILS as TRUSTED_TYPES_DETAILS


SECURITY_CONTEXTS = {
    "trusted-types": TRUSTED_TYPES_DETAILS,
    "csp-strict-dynamic": CSP_STRICT_DYNAMIC_DETAILS,
    "sanitizer-api": SANITIZER_API_DETAILS,
    "origin-trial": ORIGIN_TRIAL_DETAILS,
    "cross-origin-isolated": CROSS_ORIGIN_ISOLATED_DETAILS,
    "shared-array-buffer": SHARED_ARRAY_BUFFER_DETAILS,
}

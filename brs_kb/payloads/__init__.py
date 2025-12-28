#!/usr/bin/env python3
"""
Project: BRS-KB (BRS XSS Knowledge Base)
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: 2025-12-26 UTC
Status: Refactored - Enterprise Structure
Telegram: https://t.me/EasyProTech

Payload database package - centralized XSS payload repository.
Enterprise-grade modular structure with logical organization.

Structure:
- core/       - Base payloads and scanner essentials
- techniques/ - XSS techniques (HOW to attack)
- vectors/    - Injection vectors (THROUGH what)
- contexts/   - Injection contexts (WHERE)
- api/        - API-specific payloads
- attacks/    - Attack types (WHAT we do)
- javascript/ - JavaScript-specific tricks
- waf/        - WAF bypass techniques
- frameworks/ - Framework-specific payloads
- browsers/   - Browser-specific payloads
- matrix/     - Matrix ecosystem payloads
- research/   - CVE, bug bounty, academic research
- sources/    - External sources with attribution
"""

# =============================================================================
# MODELS & UTILITIES
# =============================================================================
# =============================================================================
# CORE - Base payloads
# =============================================================================
from brs_kb.version import PAYLOAD_DB_VERSION

from .api.brs_kb_beacon import BEACON_PAYLOADS
from .api.brs_kb_fetch import FETCH_PAYLOADS
from .api.brs_kb_file import FILE_API_PAYLOADS
from .api.brs_kb_graphql import GRAPHQL_PAYLOADS
from .api.brs_kb_history import HISTORY_PAYLOADS
from .api.brs_kb_messaging import BROADCAST_PAYLOADS, MESSAGE_CHANNEL_PAYLOADS
from .api.brs_kb_misc_api import FULLSCREEN_PAYLOADS, VIBRATION_PAYLOADS

# =============================================================================
# API - Modern browser APIs
# =============================================================================
from .api.brs_kb_modern_apis import MODERN_BROWSER_APIS_PAYLOADS
from .api.brs_kb_observers import (
    INTERSECTION_OBSERVER_PAYLOADS,
    MUTATION_OBSERVER_PAYLOADS,
    RESIZE_OBSERVER_PAYLOADS,
)
from .api.brs_kb_performance import PERFORMANCE_PAYLOADS
from .api.brs_kb_postmessage import POSTMESSAGE_PAYLOADS
from .api.brs_kb_serviceworker import SERVICE_WORKER_PAYLOADS
from .api.brs_kb_sse import SSE_PAYLOADS
from .api.brs_kb_storage import INDEXEDDB_PAYLOADS, STORAGE_XSS_PAYLOADS
from .api.brs_kb_storage_apis import STORAGE_APIS_PAYLOADS
from .api.brs_kb_url import URL_API_PAYLOADS
from .api.brs_kb_webgl import WEBGL_PAYLOADS
from .api.brs_kb_webrtc import WEBRTC_PAYLOADS

# =============================================================================
# API - API-specific payloads
# =============================================================================
from .api.brs_kb_websocket import WEBSOCKET_PAYLOADS, WEBSOCKET_XSS_PAYLOADS
from .api.brs_kb_workers import WORKER_PAYLOADS
from .attacks.brs_kb_blind import BLIND_XSS_PAYLOADS
from .attacks.brs_kb_clickjack import CLICKJACK_PAYLOADS
from .attacks.brs_kb_defacement import DEFACEMENT_PAYLOADS

# =============================================================================
# ATTACKS - Attack types
# =============================================================================
from .attacks.brs_kb_exfiltration import (
    CLIPBOARD_PAYLOADS,
    COOKIE_STEALING_PAYLOADS,
    GEOLOCATION_PAYLOADS,
    MEDIA_DEVICE_PAYLOADS,
)
from .attacks.brs_kb_keylogger import KEYLOGGER_PAYLOADS
from .attacks.brs_kb_phishing import FORM_HIJACK_PAYLOADS, NOTIFICATION_PAYLOADS, PHISHING_PAYLOADS
from .attacks.brs_kb_redirect import REDIRECT_PAYLOADS
from .attacks.brs_kb_session import SESSION_HIJACK_PAYLOADS

# =============================================================================
# BROWSERS - Browser-specific
# =============================================================================
from .browsers.brs_kb_browser_all import BROWSER_SPECIFIC_DATABASE
from .browsers.brs_kb_browser_flash import FLASH_LEGACY_DATABASE
from .browsers.brs_kb_browser_ie import IE_LEGACY_DATABASE
from .browsers.brs_kb_browser_quirks import BROWSER_SPECIFIC_PAYLOADS
from .context_specific.brs_kb_ctx_electron import ELECTRON_XSS_DATABASE
from .context_specific.brs_kb_ctx_email import EMAIL_XSS_PAYLOADS
from .context_specific.brs_kb_ctx_headers import HTTP_HEADER_XSS_DATABASE

# =============================================================================
# CONTEXTS - Injection contexts
# =============================================================================
from .context_specific.brs_kb_ctx_json import JSON_INJECTION_PAYLOADS
from .context_specific.brs_kb_ctx_markdown import MARKDOWN_XSS_PAYLOADS
from .context_specific.brs_kb_ctx_oembed import OEMBED_XSS_DATABASE
from .context_specific.brs_kb_ctx_pdf import PDF_XSS_DATABASE
from .context_specific.brs_kb_ctx_rare import RARE_CONTEXTS_DATABASE
from .context_specific.brs_kb_ctx_redirect import OPEN_REDIRECT_XSS_DATABASE
from .context_specific.brs_kb_ctx_rss import RSS_ATOM_DATABASE
from .context_specific.brs_kb_ctx_ssti import SSTI_XSS_DATABASE
from .context_specific.brs_kb_ctx_upload import FILE_UPLOAD_XSS_DATABASE
from .core.brs_kb_advanced import ADVANCED_PAYLOAD_DATABASE
from .core.brs_kb_base import CONTEXTS_COVERED, PAYLOAD_DATABASE, TOTAL_PAYLOADS
from .core.brs_kb_base_advanced import ADVANCED_BASE_PAYLOADS
from .core.brs_kb_base_comprehensive import COMPREHENSIVE_BASE_PAYLOADS
from .core.brs_kb_base_context import CONTEXT_BASE_PAYLOADS
from .core.brs_kb_base_html import HTML_BASE_PAYLOADS
from .core.brs_kb_base_modern import MODERN_BASE_PAYLOADS
from .core.brs_kb_core import CORE_PAYLOAD_DATABASE
from .core.brs_kb_core_polyglot import POLYGLOT_CORE_PAYLOADS
from .core.brs_kb_extended import (
    EXOTIC_PAYLOADS,
    EXTENDED_PAYLOAD_DATABASE,
    MODERN_BROWSER_PAYLOADS,
    WAF_BYPASS_2024_PAYLOADS,
)
from .core.brs_kb_scanner import SCANNER_PAYLOADS

# =============================================================================
# ENRICHMENT - Additional payloads for low-coverage contexts
# =============================================================================
from .enrichment.brs_kb_context_enrichment import CONTEXT_ENRICHMENT_PAYLOADS
from .enrichment.brs_kb_critical_enrichment import CRITICAL_ENRICHMENT_PAYLOADS
from .enrichment.brs_kb_lowcov_enrichment import LOWCOV_ENRICHMENT_PAYLOADS
from .enrichment.brs_kb_priority_enrichment import PRIORITY_ENRICHMENT_PAYLOADS

# =============================================================================
# EXTERNAL SOURCES - Community and researcher contributions
# =============================================================================
from .external_sources import EXTERNAL_SOURCES_DATABASE
from .frameworks.brs_kb_fw_all import FRAMEWORK_PAYLOAD_DATABASE
from .frameworks.brs_kb_fw_alpine import ALPINE_EXTENDED_PAYLOADS, ALPINE_PAYLOADS
from .frameworks.brs_kb_fw_angular import ANGULAR_PAYLOADS
from .frameworks.brs_kb_fw_htmx import HTMX_PAYLOADS
from .frameworks.brs_kb_fw_modern import MODERN_FRAMEWORKS_PAYLOADS

# =============================================================================
# FRAMEWORKS - Framework-specific
# =============================================================================
from .frameworks.brs_kb_fw_react import REACT_PAYLOADS
from .frameworks.brs_kb_fw_vue import VUE_PAYLOADS
from .info import get_database_info

# =============================================================================
# JAVASCRIPT - JavaScript tricks
# =============================================================================
from .javascript.brs_kb_js_async import ASYNC_GENERATOR_PAYLOADS, TIMER_PAYLOADS
from .javascript.brs_kb_js_methods import ARRAY_METHOD_PAYLOADS, STRING_METHOD_PAYLOADS
from .javascript.brs_kb_js_modern import (
    BIGINT_PAYLOADS,
    MODERN_SYNTAX_PAYLOADS,
    PRIVATE_FIELD_PAYLOADS,
    SYMBOL_PAYLOADS,
)
from .javascript.brs_kb_js_objects import (
    DATE_PAYLOADS,
    FINALIZATION_PAYLOADS,
    GLOBAL_OBJECTS_PAYLOADS,
    INTL_PAYLOADS,
    JSON_PAYLOADS,
    MATH_PAYLOADS,
    OBJECT_METHOD_PAYLOADS,
    PROTOTYPE_METHOD_PAYLOADS,
    PROXY_PAYLOADS,
    REFLECT_PAYLOADS,
    REGEXP_PAYLOADS,
    WRAPPER_PAYLOADS,
)
from .javascript.brs_kb_js_syntax import (
    COMPUTED_PROPERTY_PAYLOADS,
    DESTRUCTURING_PAYLOADS,
    SHORTHAND_PAYLOADS,
    SPREAD_PAYLOADS,
    TAGGED_TEMPLATE_PAYLOADS,
)
from .matrix.brs_kb_matrix_bridges import BRS_KB_MATRIX_BRIDGES_PAYLOADS
from .matrix.brs_kb_matrix_clients import BRS_KB_MATRIX_CLIENTS_PAYLOADS

# =============================================================================
# MATRIX - Matrix ecosystem
# =============================================================================
from .matrix.brs_kb_matrix_core import BRS_KB_MATRIX_CORE_PAYLOADS
from .matrix.brs_kb_matrix_enterprise import BRS_KB_MATRIX_ENTERPRISE_PAYLOADS
from .models import PayloadEntry

# =============================================================================
# MODERN - Modern Web APIs
# =============================================================================
from .modern import MODERN_API_PAYLOADS, MODERN_API_TOTAL_PAYLOADS
from .modern.brs_kb_html5_apis import HTML5_MODERN_APIS_PAYLOADS
from .operations import add_payload, export_payloads, get_all_payloads
from .queries import (
    get_payload_by_id,
    get_payloads_by_context,
    get_payloads_by_severity,
    get_payloads_by_tag,
    get_waf_bypass_payloads,
)
from .research.brs_kb_academic import BRS_KB_RESEARCH_PAPERS_PAYLOADS
from .research.brs_kb_advanced_research import BRS_KB_ULTRA_DEEP_PAYLOADS
from .research.brs_kb_bugbounty import BRS_KB_BUGBOUNTY_REAL_PAYLOADS
from .research.brs_kb_ctf import BRS_KB_CTF_BUGBOUNTY_PAYLOADS

# =============================================================================
# RESEARCH - CVE, bug bounty, academic
# =============================================================================
from .research.brs_kb_cve import BRS_KB_1DAY_CVE_PAYLOADS
from .research.brs_kb_deep import BRS_KB_DEEP_MEMORY_PAYLOADS
from .research.brs_kb_extended_research import BRS_KB_FINAL_FRONTIER_PAYLOADS
from .research.brs_kb_extra import BRS_KB_ABSOLUTE_FINAL_PAYLOADS
from .research.brs_kb_historical import BRS_KB_HISTORICAL_PAYLOADS
from .research.brs_kb_supplementary import BRS_KB_TRULY_LAST_PAYLOADS
from .search import search_payloads

# =============================================================================
# SECURITY - Security mechanism bypasses
# =============================================================================
from .security.brs_kb_security_bypass import SECURITY_BYPASS_PAYLOADS

# =============================================================================
# SOURCES - External sources with attribution
# =============================================================================
from .sources.brs_kb_src_brutelogic import BRS_KB_BRUTELOGIC_2020_DATABASE
from .sources.brs_kb_src_kinugawa import BRS_KB_KINUGAWA_FILTERBYPASS_DATABASE
from .sources.brs_kb_src_seclists import BRS_KB_SECLISTS_DATABASE

# =============================================================================
# TECHNIQUES - Advanced XSS techniques
# =============================================================================
from .techniques.brs_kb_advanced_techniques import ADVANCED_TECHNIQUES_PAYLOADS
from .techniques.brs_kb_code_exec import EVAL_LIKE_PAYLOADS
from .techniques.brs_kb_csp_bypass import CSP_BYPASS_PAYLOADS

# =============================================================================
# TECHNIQUES - XSS techniques
# =============================================================================
from .techniques.brs_kb_dom import DOCUMENT_PAYLOADS, LOCATION_PAYLOADS, REFLECTED_DOM_PAYLOADS
from .techniques.brs_kb_dom_clobbering import DOM_CLOBBERING_PAYLOADS
from .techniques.brs_kb_encoding import (
    ENCODING_PAYLOADS,
    ENCODING_TRICKS_PAYLOADS,
    UNICODE_PAYLOADS,
)
from .techniques.brs_kb_injection import CRLF_XSS_PAYLOADS, HPP_PAYLOADS
from .techniques.brs_kb_mutation import MUTATION_XSS_PAYLOADS
from .techniques.brs_kb_obfuscation import OBFUSCATION_ADVANCED_PAYLOADS, OBFUSCATION_PAYLOADS
from .techniques.brs_kb_polyglots import POLYGLOT_PAYLOADS
from .techniques.brs_kb_scriptless import SCRIPTLESS_PAYLOADS
from .testing import test_payload_effectiveness
from .vectors.brs_kb_attributes import ATTRIBUTE_INJECTION_PAYLOADS
from .vectors.brs_kb_attributes import ATTRIBUTE_INJECTION_PAYLOADS as ATTR_INJECTION_PAYLOADS
from .vectors.brs_kb_css import CSS_XSS_PAYLOADS

# =============================================================================
# VECTORS - Advanced CSS and Attributes
# =============================================================================
from .vectors.brs_kb_css_advanced import CSS_ADVANCED_PAYLOADS
from .vectors.brs_kb_events import EVENT_CONSTRUCTOR_PAYLOADS, EVENT_HANDLER_PAYLOADS
from .vectors.brs_kb_html5 import HTML5_PAYLOADS

# =============================================================================
# VECTORS - Injection vectors
# =============================================================================
from .vectors.brs_kb_html_tags import (
    COMMENT_INJECTION_PAYLOADS,
    HTML_TAG_PAYLOADS,
    HTML_TAGS_DATABASE,
)
from .vectors.brs_kb_html_tags_exotic_part1 import EXOTIC_PAYLOADS_PART1
from .vectors.brs_kb_html_tags_exotic_part2 import EXOTIC_PAYLOADS_PART2
from .vectors.brs_kb_html_tags_html5 import HTML5_MODERN_API_PAYLOADS
from .vectors.brs_kb_html_tags_portswigger_sobky_terjanq import PORT_SWIGGER_SOBKY_TERJANQ_PAYLOADS
from .vectors.brs_kb_mathml import MATHML_PAYLOADS
from .vectors.brs_kb_protocols import PROTOCOL_HANDLER_PAYLOADS
from .vectors.brs_kb_shadow_dom import SHADOW_DOM_PAYLOADS
from .vectors.brs_kb_svg import SVG_PAYLOADS
from .vectors.brs_kb_webcomponents import WEB_COMPONENT_PAYLOADS
from .waf.brs_kb_waf_2025 import WAF_BYPASS_2025_DATABASE
from .waf.brs_kb_waf_akamai import AKAMAI_BYPASS_PAYLOADS
from .waf.brs_kb_waf_all import BRS_KB_WAF_COMPLETE_PAYLOADS
from .waf.brs_kb_waf_aws import AWS_WAF_BYPASS_PAYLOADS
from .waf.brs_kb_waf_barracuda import BARRACUDA_BYPASS_PAYLOADS

# =============================================================================
# WAF - WAF bypass techniques
# =============================================================================
from .waf.brs_kb_waf_cloudflare import CLOUDFLARE_BYPASS_PAYLOADS
from .waf.brs_kb_waf_f5 import F5_BYPASS_PAYLOADS
from .waf.brs_kb_waf_fortiweb import FORTIWEB_BYPASS_PAYLOADS
from .waf.brs_kb_waf_imperva import IMPERVA_BYPASS_PAYLOADS
from .waf.brs_kb_waf_modsecurity import MODSECURITY_BYPASS_PAYLOADS
from .waf.brs_kb_waf_sanitizers import SANITIZER_BYPASSES_DATABASE
from .waf.brs_kb_waf_sucuri import SUCURI_BYPASS_PAYLOADS
from .waf.brs_kb_waf_wordfence import WORDFENCE_BYPASS_PAYLOADS


# =============================================================================
# COMBINED DATABASE
# =============================================================================
FULL_PAYLOAD_DATABASE = {
    # Core
    **PAYLOAD_DATABASE,
    **SCANNER_PAYLOADS,
    **CORE_PAYLOAD_DATABASE,
    **ADVANCED_PAYLOAD_DATABASE,
    **EXTENDED_PAYLOAD_DATABASE,
    **MODERN_BROWSER_PAYLOADS,
    **WAF_BYPASS_2024_PAYLOADS,
    **EXOTIC_PAYLOADS,
    **ADVANCED_BASE_PAYLOADS,
    **COMPREHENSIVE_BASE_PAYLOADS,
    **CONTEXT_BASE_PAYLOADS,
    **HTML_BASE_PAYLOADS,
    **MODERN_BASE_PAYLOADS,
    **POLYGLOT_CORE_PAYLOADS,
    # Techniques
    **REFLECTED_DOM_PAYLOADS,
    **DOCUMENT_PAYLOADS,
    **LOCATION_PAYLOADS,
    **MUTATION_XSS_PAYLOADS,
    **ENCODING_TRICKS_PAYLOADS,
    **ENCODING_PAYLOADS,
    **UNICODE_PAYLOADS,
    **OBFUSCATION_ADVANCED_PAYLOADS,
    **OBFUSCATION_PAYLOADS,
    **POLYGLOT_PAYLOADS,
    **CSP_BYPASS_PAYLOADS,
    **DOM_CLOBBERING_PAYLOADS,
    **SCRIPTLESS_PAYLOADS,
    **CRLF_XSS_PAYLOADS,
    **HPP_PAYLOADS,
    **EVAL_LIKE_PAYLOADS,
    # Vectors
    **HTML_TAG_PAYLOADS,
    **COMMENT_INJECTION_PAYLOADS,
    **HTML_TAGS_DATABASE,
    **PORT_SWIGGER_SOBKY_TERJANQ_PAYLOADS,
    **EXOTIC_PAYLOADS_PART1,
    **EXOTIC_PAYLOADS_PART2,
    **HTML5_MODERN_API_PAYLOADS,
    **EVENT_HANDLER_PAYLOADS,
    **EVENT_CONSTRUCTOR_PAYLOADS,
    **ATTRIBUTE_INJECTION_PAYLOADS,
    **SVG_PAYLOADS,
    **MATHML_PAYLOADS,
    **CSS_XSS_PAYLOADS,
    **PROTOCOL_HANDLER_PAYLOADS,
    **HTML5_PAYLOADS,
    **SHADOW_DOM_PAYLOADS,
    **WEB_COMPONENT_PAYLOADS,
    # Contexts
    **JSON_INJECTION_PAYLOADS,
    **EMAIL_XSS_PAYLOADS,
    **MARKDOWN_XSS_PAYLOADS,
    **PDF_XSS_DATABASE,
    **RSS_ATOM_DATABASE,
    **SSTI_XSS_DATABASE,
    **FILE_UPLOAD_XSS_DATABASE,
    **HTTP_HEADER_XSS_DATABASE,
    **OEMBED_XSS_DATABASE,
    **RARE_CONTEXTS_DATABASE,
    **OPEN_REDIRECT_XSS_DATABASE,
    **ELECTRON_XSS_DATABASE,
    # API
    **WEBSOCKET_XSS_PAYLOADS,
    **WEBSOCKET_PAYLOADS,
    **GRAPHQL_PAYLOADS,
    **SSE_PAYLOADS,
    **POSTMESSAGE_PAYLOADS,
    **STORAGE_XSS_PAYLOADS,
    **INDEXEDDB_PAYLOADS,
    **SERVICE_WORKER_PAYLOADS,
    **FETCH_PAYLOADS,
    **WORKER_PAYLOADS,
    **MUTATION_OBSERVER_PAYLOADS,
    **INTERSECTION_OBSERVER_PAYLOADS,
    **RESIZE_OBSERVER_PAYLOADS,
    **BROADCAST_PAYLOADS,
    **MESSAGE_CHANNEL_PAYLOADS,
    **URL_API_PAYLOADS,
    **FILE_API_PAYLOADS,
    **HISTORY_PAYLOADS,
    **BEACON_PAYLOADS,
    **WEBGL_PAYLOADS,
    **WEBRTC_PAYLOADS,
    **PERFORMANCE_PAYLOADS,
    **VIBRATION_PAYLOADS,
    **FULLSCREEN_PAYLOADS,
    # Attacks
    **COOKIE_STEALING_PAYLOADS,
    **CLIPBOARD_PAYLOADS,
    **GEOLOCATION_PAYLOADS,
    **MEDIA_DEVICE_PAYLOADS,
    **KEYLOGGER_PAYLOADS,
    **PHISHING_PAYLOADS,
    **FORM_HIJACK_PAYLOADS,
    **NOTIFICATION_PAYLOADS,
    **SESSION_HIJACK_PAYLOADS,
    **DEFACEMENT_PAYLOADS,
    **REDIRECT_PAYLOADS,
    **CLICKJACK_PAYLOADS,
    **BLIND_XSS_PAYLOADS,
    # JavaScript
    **ASYNC_GENERATOR_PAYLOADS,
    **TIMER_PAYLOADS,
    **ARRAY_METHOD_PAYLOADS,
    **STRING_METHOD_PAYLOADS,
    **PROXY_PAYLOADS,
    **FINALIZATION_PAYLOADS,
    **INTL_PAYLOADS,
    **MATH_PAYLOADS,
    **JSON_PAYLOADS,
    **REGEXP_PAYLOADS,
    **DATE_PAYLOADS,
    **WRAPPER_PAYLOADS,
    **REFLECT_PAYLOADS,
    **GLOBAL_OBJECTS_PAYLOADS,
    **OBJECT_METHOD_PAYLOADS,
    **PROTOTYPE_METHOD_PAYLOADS,
    **MODERN_SYNTAX_PAYLOADS,
    **BIGINT_PAYLOADS,
    **PRIVATE_FIELD_PAYLOADS,
    **SYMBOL_PAYLOADS,
    **DESTRUCTURING_PAYLOADS,
    **SPREAD_PAYLOADS,
    **TAGGED_TEMPLATE_PAYLOADS,
    **COMPUTED_PROPERTY_PAYLOADS,
    **SHORTHAND_PAYLOADS,
    # WAF
    **CLOUDFLARE_BYPASS_PAYLOADS,
    **AKAMAI_BYPASS_PAYLOADS,
    **AWS_WAF_BYPASS_PAYLOADS,
    **IMPERVA_BYPASS_PAYLOADS,
    **F5_BYPASS_PAYLOADS,
    **MODSECURITY_BYPASS_PAYLOADS,
    **SUCURI_BYPASS_PAYLOADS,
    **WORDFENCE_BYPASS_PAYLOADS,
    **FORTIWEB_BYPASS_PAYLOADS,
    **BARRACUDA_BYPASS_PAYLOADS,
    **SANITIZER_BYPASSES_DATABASE,
    **BRS_KB_WAF_COMPLETE_PAYLOADS,
    **WAF_BYPASS_2025_DATABASE,
    # Frameworks
    **REACT_PAYLOADS,
    **VUE_PAYLOADS,
    **ANGULAR_PAYLOADS,
    **FRAMEWORK_PAYLOAD_DATABASE,
    **ALPINE_PAYLOADS,
    **ALPINE_EXTENDED_PAYLOADS,
    **HTMX_PAYLOADS,
    **MODERN_FRAMEWORKS_PAYLOADS,
    # Modern APIs
    **MODERN_API_PAYLOADS,
    **HTML5_MODERN_APIS_PAYLOADS,
    # Advanced CSS and Attributes
    **CSS_ADVANCED_PAYLOADS,
    **ATTR_INJECTION_PAYLOADS,
    # Security bypasses
    **SECURITY_BYPASS_PAYLOADS,
    # Browser APIs
    **MODERN_BROWSER_APIS_PAYLOADS,
    **STORAGE_APIS_PAYLOADS,
    # Advanced techniques
    **ADVANCED_TECHNIQUES_PAYLOADS,
    # Browsers
    **BROWSER_SPECIFIC_DATABASE,
    **BROWSER_SPECIFIC_PAYLOADS,
    **IE_LEGACY_DATABASE,
    **FLASH_LEGACY_DATABASE,
    # Matrix
    **BRS_KB_MATRIX_CORE_PAYLOADS,
    **BRS_KB_MATRIX_CLIENTS_PAYLOADS,
    **BRS_KB_MATRIX_BRIDGES_PAYLOADS,
    **BRS_KB_MATRIX_ENTERPRISE_PAYLOADS,
    # Research
    **BRS_KB_1DAY_CVE_PAYLOADS,
    **BRS_KB_BUGBOUNTY_REAL_PAYLOADS,
    **BRS_KB_RESEARCH_PAPERS_PAYLOADS,
    **BRS_KB_HISTORICAL_PAYLOADS,
    **BRS_KB_CTF_BUGBOUNTY_PAYLOADS,
    **BRS_KB_DEEP_MEMORY_PAYLOADS,
    **BRS_KB_ULTRA_DEEP_PAYLOADS,
    **BRS_KB_FINAL_FRONTIER_PAYLOADS,
    **BRS_KB_ABSOLUTE_FINAL_PAYLOADS,
    **BRS_KB_TRULY_LAST_PAYLOADS,
    # Sources
    **BRS_KB_BRUTELOGIC_2020_DATABASE,
    **BRS_KB_KINUGAWA_FILTERBYPASS_DATABASE,
    **BRS_KB_SECLISTS_DATABASE,
    # External Sources
    **EXTERNAL_SOURCES_DATABASE,
    # Enrichment
    **CONTEXT_ENRICHMENT_PAYLOADS,
    **LOWCOV_ENRICHMENT_PAYLOADS,
    **PRIORITY_ENRICHMENT_PAYLOADS,
    **CRITICAL_ENRICHMENT_PAYLOADS,
}

FULL_TOTAL_PAYLOADS = len(FULL_PAYLOAD_DATABASE)

# =============================================================================
# EXPORTS
# =============================================================================
__all__ = [
    "CONTEXTS_COVERED",
    "CORE_PAYLOAD_DATABASE",
    "FULL_PAYLOAD_DATABASE",
    "FULL_TOTAL_PAYLOADS",
    # Databases
    "PAYLOAD_DATABASE",
    # Metadata
    "PAYLOAD_DB_VERSION",
    "SCANNER_PAYLOADS",
    "TOTAL_PAYLOADS",
    # Models & Utils
    "PayloadEntry",
    "add_payload",
    "export_payloads",
    "get_all_payloads",
    "get_database_info",
    "get_payload_by_id",
    "get_payloads_by_context",
    "get_payloads_by_severity",
    "get_payloads_by_tag",
    "get_waf_bypass_payloads",
    "search_payloads",
    "test_payload_effectiveness",
]

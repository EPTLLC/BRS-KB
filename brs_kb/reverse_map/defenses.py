#!/usr/bin/env python3

"""
Project: BRS-KB (BRS XSS Knowledge Base)
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: 2025-12-04 12:00:00 UTC
Status: Created
Telegram: https://t.me/easyprotech

Reverse mapping defenses
Defense strategies and mappings for XSS contexts
"""

# Enhanced Defense → Effectiveness mapping with modern techniques
DEFENSE_TO_EFFECTIVENESS = {
    "html_encoding": {
        "effective_against": ["html_content", "html_attribute", "html_comment"],
        "implementation": [
            "htmlspecialchars($input, ENT_QUOTES, 'UTF-8')",  # PHP
            "html.escape(input, quote=True)",  # Python
            "element.textContent = input",  # JavaScript
        ],
        "bypass_difficulty": "high",
        "tags": ["encoding", "output_sanitization"],
    },
    "csp": {
        "effective_against": [
            "html_content",
            "javascript",
            "css",
            "svg",
            "template_injection",
            "websocket",
        ],
        "implementation": [
            "Content-Security-Policy: default-src 'self'; script-src 'nonce-{random}'; object-src 'none'"
        ],
        "bypass_difficulty": "very_high",
        "tags": ["policy", "browser_enforcement"],
    },
    "javascript_encoding": {
        "effective_against": ["js_string", "javascript"],
        "implementation": [
            "JSON.stringify(input)",
            "json.dumps(input)",
            "json_encode($input, JSON_HEX_TAG)",
        ],
        "bypass_difficulty": "high",
        "tags": ["serialization", "json_security"],
    },
    "url_validation": {
        "effective_against": ["url", "html_attribute"],
        "implementation": [
            "new URL(input, base)",  # JavaScript
            "urllib.parse.urlparse(input)",  # Python
            "parse_url($input)",  # PHP
        ],
        "bypass_difficulty": "medium",
        "tags": ["url_parsing", "protocol_validation"],
    },
    "sanitization": {
        "effective_against": ["html_content", "svg", "markdown", "xml"],
        "implementation": [
            "DOMPurify.sanitize(input)",  # JavaScript
            "bleach.clean(input)",  # Python
            "HTMLPurifier",  # PHP
        ],
        "bypass_difficulty": "medium",
        "tags": ["html_sanitization", "dom_cleaning"],
    },
    # New modern defenses
    "trusted_types": {
        "effective_against": ["html_content", "javascript", "dom_xss"],
        "implementation": [
            "trustedTypes.createPolicy('default', { createHTML: (s) => DOMPurify.sanitize(s) })"
        ],
        "bypass_difficulty": "very_high",
        "tags": ["browser_api", "modern_security"],
    },
    "csp_nonce": {
        "effective_against": ["html_content", "javascript"],
        "implementation": [
            "<script nonce='{random}'>...</script>",
            "Content-Security-Policy: script-src 'nonce-{random}'",
        ],
        "bypass_difficulty": "very_high",
        "tags": ["csp_enhancement", "inline_script_control"],
    },
    "waf_rules": {
        "effective_against": "all",
        "implementation": [
            "ModSecurity rules for XSS detection",
            "AWS WAF XSS protection",
            "Cloudflare XSS detection",
        ],
        "bypass_difficulty": "high",
        "tags": ["waf", "perimeter_security"],
    },
}

# Enhanced Context → Recommended defenses with modern contexts
CONTEXT_TO_DEFENSES = {
    "html_content": [
        {"defense": "html_encoding", "priority": 1, "required": True, "tags": ["primary"]},
        {"defense": "csp", "priority": 1, "required": True, "tags": ["policy"]},
        {"defense": "sanitization", "priority": 2, "required": False, "tags": ["fallback"]},
    ],
    "html_attribute": [
        {"defense": "html_encoding", "priority": 1, "required": True, "tags": ["encoding"]},
        {"defense": "url_validation", "priority": 1, "required": True, "tags": ["validation"]},
        {"defense": "csp", "priority": 2, "required": True, "tags": ["policy"]},
    ],
    "javascript": [
        {"defense": "csp_nonce", "priority": 1, "required": True, "tags": ["modern", "inline"]},
        {"defense": "javascript_encoding", "priority": 1, "required": True, "tags": ["encoding"]},
        {"defense": "csp", "priority": 1, "required": True, "tags": ["policy"]},
    ],
    "js_string": [
        {"defense": "javascript_encoding", "priority": 1, "required": True, "tags": ["primary"]},
        {"defense": "json_serialization", "priority": 1, "required": True, "tags": ["json"]},
        {"defense": "csp", "priority": 2, "required": True, "tags": ["policy"]},
    ],
    "url": [
        {"defense": "url_validation", "priority": 1, "required": True, "tags": ["primary"]},
        {"defense": "protocol_whitelist", "priority": 1, "required": True, "tags": ["whitelist"]},
        {"defense": "csp", "priority": 2, "required": True, "tags": ["policy"]},
    ],
    # New modern contexts
    "websocket": [
        {"defense": "input_validation", "priority": 1, "required": True, "tags": ["websocket"]},
        {"defense": "csp", "priority": 1, "required": True, "tags": ["policy"]},
        {"defense": "message_filtering", "priority": 1, "required": True, "tags": ["real-time"]},
    ],
    "service_worker": [
        {"defense": "service_worker_validation", "priority": 1, "required": True, "tags": ["sw"]},
        {"defense": "csp", "priority": 1, "required": True, "tags": ["policy"]},
        {
            "defense": "registration_control",
            "priority": 1,
            "required": True,
            "tags": ["registration"],
        },
    ],
    "webrtc": [
        {"defense": "webrtc_validation", "priority": 1, "required": True, "tags": ["webrtc"]},
        {"defense": "media_control", "priority": 1, "required": True, "tags": ["media"]},
        {"defense": "csp", "priority": 2, "required": True, "tags": ["policy"]},
    ],
    "indexeddb": [
        {"defense": "storage_validation", "priority": 1, "required": True, "tags": ["storage"]},
        {"defense": "data_sanitization", "priority": 1, "required": True, "tags": ["sanitization"]},
        {"defense": "access_control", "priority": 2, "required": False, "tags": ["permissions"]},
    ],
    "webgl": [
        {"defense": "shader_validation", "priority": 1, "required": True, "tags": ["shader"]},
        {"defense": "webgl_sandbox", "priority": 1, "required": True, "tags": ["sandbox"]},
        {"defense": "csp", "priority": 2, "required": True, "tags": ["policy"]},
    ],
    "template_injection": [
        {"defense": "template_sandboxing", "priority": 1, "required": True, "tags": ["sandbox"]},
        {"defense": "aot_compilation", "priority": 1, "required": True, "tags": ["compilation"]},
        {"defense": "csp", "priority": 1, "required": True, "tags": ["policy"]},
    ],
    "dom_xss": [
        {
            "defense": "trusted_types",
            "priority": 1,
            "required": True,
            "tags": ["modern", "browser"],
        },
        {"defense": "dom_sanitization", "priority": 1, "required": True, "tags": ["dom"]},
        {"defense": "csp", "priority": 2, "required": True, "tags": ["policy"]},
    ],
}

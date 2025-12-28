#!/usr/bin/env python3

"""
Project: BRS-KB (BRS XSS Knowledge Base)
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: 2025-12-26 UTC
Status: Created
Telegram: https://t.me/EasyProTech

Knowledge Base: Web Bluetooth API XSS
"""

DETAILS = {
    "title": "Cross-Site Scripting (XSS) via Web Bluetooth API",
    "severity": "critical",
    "cvss_score": 8.8,
    "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H",
    "reliability": "high",
    "cwe": ["CWE-79", "CWE-922"],
    "owasp": ["A03:2021"],
    "tags": ["xss", "bluetooth", "ble", "hardware", "chrome-56", "critical"],
    "description": """
Web Bluetooth API (Chrome 56+) allows web apps to communicate with Bluetooth devices.
XSS vulnerabilities occur when user input controls device selection, characteristic values,
or service UUIDs without validation.

SEVERITY: CRITICAL
Direct Bluetooth access can lead to device manipulation, data exfiltration, and privacy violations.
""",
    "attack_vector": """
WEB BLUETOOTH DEVICE SELECTION:
const device = await navigator.bluetooth.requestDevice({
  filters: [{ name: userInput }]  // XSS if name is controlled
});

WEB BLUETOOTH CHARACTERISTIC VALUE:
const device = await navigator.bluetooth.requestDevice({ filters: [] });
const server = await device.gatt.connect();
const service = await server.getPrimaryService('battery_service');
const characteristic = await service.getCharacteristic('battery_level');
const value = await characteristic.readValue();
const text = new TextDecoder().decode(value);
document.body.innerHTML = text;  // XSS if value contains HTML

WEB BLUETOOTH WRITE VALUE:
const value = new TextEncoder().encode(userInput);
await characteristic.writeValue(value);  // XSS if value is malicious

WEB BLUETOOTH SERVICE UUID:
const service = await server.getPrimaryService(userInput);  // XSS if UUID is controlled

WEB BLUETOOTH DESCRIPTOR:
const descriptor = await characteristic.getDescriptor(userInput);  // XSS
const value = await descriptor.readValue();
""",
    "remediation": """
DEFENSE:

1. Whitelist allowed Bluetooth service/characteristic UUIDs
2. Validate all characteristic values before display
3. Sanitize device names and descriptors
4. Restrict Web Bluetooth to trusted origins
5. Implement device access permissions

SAFE PATTERN:
const allowedServices = ['battery_service', 'device_information'];
if (!allowedServices.includes(userInput)) {
  throw new Error('Service not allowed');
}
const service = await server.getPrimaryService(userInput);

VALUE SANITIZATION:
const value = await characteristic.readValue();
const text = new TextDecoder().decode(value);
element.textContent = text;  // Safe
// Or
element.innerHTML = DOMPurify.sanitize(text);

OWASP REFERENCES:
- CWE-79: Cross-site Scripting
- CWE-922: Insecure Storage
- Web Bluetooth API Specification
""",
}

#!/usr/bin/env python3

"""
Project: BRS-KB (BRS XSS Knowledge Base)
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: 2025-12-26 UTC
Status: Created
Telegram: https://t.me/EasyProTech

Knowledge Base: Web USB API XSS
"""

DETAILS = {
    "title": "Cross-Site Scripting (XSS) via Web USB API",
    "severity": "critical",
    "cvss_score": 9.0,
    "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H",
    "reliability": "high",
    "cwe": ["CWE-79", "CWE-922"],
    "owasp": ["A03:2021"],
    "tags": ["xss", "usb", "hardware", "device-access", "chrome-61", "critical"],
    "description": """
Web USB API (Chrome 61+) allows web apps to communicate with USB devices. XSS vulnerabilities
occur when user input controls USB device selection, data transfer, or device descriptors
without validation.

SEVERITY: CRITICAL
Direct hardware access can lead to device manipulation, firmware attacks, and data exfiltration.
""",
    "attack_vector": """
WEB USB DEVICE SELECTION:
const device = await navigator.usb.requestDevice({
  filters: [{ vendorId: userInput }]  // XSS if vendorId is controlled
});

WEB USB TRANSFER INJECTION:
const device = await navigator.usb.requestDevice({ filters: [] });
await device.open();
await device.claimInterface(0);
await device.transferOut(1, new Uint8Array(userInput));  // XSS if data is malicious

WEB USB DESCRIPTOR INJECTION:
const device = await navigator.usb.requestDevice({ filters: [] });
const descriptor = await device.getConfiguration();
const html = descriptor.configurationName;  // XSS if descriptor contains HTML
document.body.innerHTML = html;

WEB USB CONTROL TRANSFER:
await device.controlTransferOut({
  requestType: 'vendor',
  request: userInput,  // XSS if request is controlled
  value: 0,
  index: 0
}, new Uint8Array([1, 2, 3]));

WEB USB INTERFACE CLAIM:
await device.claimInterface(userInput);  // XSS if interface number is controlled
""",
    "remediation": """
DEFENSE:

1. Whitelist allowed USB device vendors/products
2. Validate all USB transfer data
3. Sanitize device descriptors before display
4. Restrict Web USB to trusted origins only
5. Implement device access permissions

SAFE PATTERN:
const allowedVendors = [0x1234, 0x5678];  // Whitelist
const filters = [{ vendorId: userInput }];
if (!allowedVendors.includes(filters[0].vendorId)) {
  throw new Error('Device not allowed');
}
const device = await navigator.usb.requestDevice({ filters });

DATA VALIDATION:
const data = new Uint8Array(userInput);
if (data.length > 64) {  // Limit size
  throw new Error('Data too large');
}
await device.transferOut(1, data);

OWASP REFERENCES:
- CWE-79: Cross-site Scripting
- CWE-922: Insecure Storage
- Web USB API Specification
""",
}

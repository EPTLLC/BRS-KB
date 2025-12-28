#!/usr/bin/env python3

"""
Project: BRS-KB (BRS XSS Knowledge Base)
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: 2025-12-26 UTC
Status: Created
Telegram: https://t.me/EasyProTech

Knowledge Base: Web Serial API XSS
"""

DETAILS = {
    "title": "Cross-Site Scripting (XSS) via Web Serial API",
    "severity": "high",
    "cvss_score": 7.8,
    "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N",
    "reliability": "high",
    "cwe": ["CWE-79", "CWE-922"],
    "owasp": ["A03:2021"],
    "tags": ["xss", "serial", "hardware", "iot", "chrome-89"],
    "description": """
Web Serial API (Chrome 89+) allows web apps to communicate with serial devices. XSS vulnerabilities
occur when user input controls serial port selection, data transfer, or device communication
without validation.

SEVERITY: HIGH
Direct serial port access can lead to device manipulation, firmware attacks, and data exfiltration.
""",
    "attack_vector": """
WEB SERIAL PORT SELECTION:
const port = await navigator.serial.requestPort({
  filters: [{ usbVendorId: userInput }]  // XSS if vendorId is controlled
});

WEB SERIAL WRITE:
const port = await navigator.serial.requestPort();
await port.open({ baudRate: 9600 });
const writer = port.writable.getWriter();
await writer.write(new TextEncoder().encode(userInput));  // XSS if data is malicious

WEB SERIAL READ:
const reader = port.readable.getReader();
const { value } = await reader.read();
const text = new TextDecoder().decode(value);
document.body.innerHTML = text;  // XSS if value contains HTML

WEB SERIAL BAUD RATE:
await port.open({ baudRate: userInput });  // XSS if baudRate causes issues

WEB SERIAL DATA TRANSFER:
const data = new Uint8Array(userInput);
await writer.write(data);  // XSS if data is malicious
""",
    "remediation": """
DEFENSE:

1. Whitelist allowed serial device vendors/products
2. Validate all serial data before rendering
3. Sanitize device descriptors
4. Restrict Web Serial to trusted origins
5. Implement device access permissions

SAFE PATTERN:
const allowedVendors = [0x1234, 0x5678];
const filters = [{ usbVendorId: userInput }];
if (!allowedVendors.includes(filters[0].usbVendorId)) {
  throw new Error('Device not allowed');
}
const port = await navigator.serial.requestPort({ filters });

DATA SANITIZATION:
const reader = port.readable.getReader();
const { value } = await reader.read();
const text = new TextDecoder().decode(value);
element.textContent = text;  // Safe
// Or
element.innerHTML = DOMPurify.sanitize(text);

OWASP REFERENCES:
- CWE-79: Cross-site Scripting
- CWE-922: Insecure Storage
- Web Serial API Specification
""",
}

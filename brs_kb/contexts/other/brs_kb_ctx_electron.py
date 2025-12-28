#!/usr/bin/env python3
# Project: BRS-KB
# Company: EasyProTech LLC (www.easypro.tech)
# Dev: Brabus
# Date: 2025-12-27 UTC
# Status: Refactored
# Telegram: https://t.me/EasyProTech

"""
Electron XSS Context

XSS in Electron applications leading to RCE.
"""

DETAILS = {
    "title": "Electron XSS to RCE",
    "severity": "critical",
    "cvss_score": 9.6,
    "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H",
    "reliability": "high",
    "cwe": ["CWE-79", "CWE-94"],
    "owasp": ["A03:2021"],
    "tags": ["electron", "nodejs", "rce", "desktop", "xss"],
    "description": """
XSS in Electron applications is critical because it can lead to Remote Code
Execution. If nodeIntegration is enabled or contextIsolation is disabled,
XSS payloads can access Node.js APIs, execute system commands, read files,
and fully compromise the user's machine.
""",
    "attack_vector": """
ELECTRON XSS TO RCE VECTORS:

1. CHILD_PROCESS.EXEC()
   require('child_process').exec('calc.exe')

2. PROCESS.MAINMODULE
   process.mainModule.require('child_process').exec('cmd')

3. FILESYSTEM ACCESS
   require('fs').readFileSync('/etc/passwd')

4. PRELOAD SCRIPT
   Exploiting exposed APIs from preload

5. WEBVIEW NODEINTEGRATION
   <webview nodeintegration src="...">
   With XSS in loaded content

6. IPCRENDERER.SEND()
   ipcRenderer.send('dangerous-channel', payload)
   If main process doesn't validate

7. REMOTE MODULE (LEGACY)
   require('@electron/remote').app.quit()

8. SHELL.OPENEXTERNAL()
   shell.openExternal('javascript:alert(1)')
   Or file:// protocol

9. PROTOCOL HANDLER
   Custom protocol leads to command execution

10. PDF VIEWER XSS
    Electron's built-in PDF viewer
""",
    "remediation": """
ELECTRON XSS/RCE PREVENTION:

1. CONTEXTISOLATION: TRUE
   webPreferences: { contextIsolation: true }
   Required for security

2. NODEINTEGRATION: FALSE
   webPreferences: { nodeIntegration: false }
   Never enable for user content

3. IMPLEMENT CSP
   Content-Security-Policy header
   Block inline scripts

4. DISABLE REMOTE MODULE
   enableRemoteModule: false

5. VALIDATE IPC MESSAGES
   Check all ipcMain handlers
   Validate message structure

6. SANDBOX RENDERERS
   webPreferences: { sandbox: true }

7. VALIDATE OPENEXTERNAL
   Never pass user URLs to shell.openExternal()
   Whitelist allowed protocols

8. UPDATE ELECTRON
   Keep Electron version current
""",
}

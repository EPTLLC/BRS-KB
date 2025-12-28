#!/usr/bin/env python3

"""
Project: BRS-KB (BRS XSS Knowledge Base)
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: 2025-12-27 UTC
Status: Created
Telegram: https://t.me/EasyProTech

Tauri Desktop Apps Context - Data Module
"""

DESCRIPTION = """
Tauri allows building desktop applications with web technologies.
Vulnerabilities occur when user input is injected into Tauri webviews,
IPC communication, or file system access, allowing XSS attacks.

Vulnerability occurs when:
- User-controlled data is injected into webview content
- IPC handlers process user input unsafely
- File system paths contain user input
- Tauri commands use unsanitized input
- Window creation uses user input

Common injection points:
- Webview content
- IPC message handlers
- File system paths
- Tauri command handlers
- Window creation parameters
"""

ATTACK_VECTOR = """
1. Webview injection:
   window.location = USER_INPUT;

2. IPC injection:
   invoke('command', { data: USER_INPUT });

3. File path injection:
   readTextFile(USER_INPUT);

4. Command handler injection:
   // In Rust:
   #[tauri::command]
   fn handler(input: String) -> String {
       format!("<div>{}</div>", input)
   }

5. Window injection:
   new Window(USER_INPUT);
"""

REMEDIATION = """
1. Sanitize all user input before rendering in webview
2. Validate IPC message handlers
3. Validate file system paths
4. Use Content Security Policy (CSP)
5. Escape HTML entities in user-controlled content
6. Audit all Tauri commands for user input
7. Validate window creation parameters
8. Use framework-safe methods for IPC communication
"""

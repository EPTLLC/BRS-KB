#!/usr/bin/env python3

"""
Project: BRS-KB (BRS XSS Knowledge Base)
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: 2025-12-27 UTC
Status: Created
Telegram: https://t.me/EasyProTech

Capacitor Mobile Apps Context - Data Module
"""

DESCRIPTION = """
Capacitor allows building mobile applications with web technologies.
Vulnerabilities occur when user input is injected into Capacitor webviews,
native plugins, or file system access, allowing XSS attacks.

Vulnerability occurs when:
- User-controlled data is injected into webview content
- Native plugin handlers process user input unsafely
- File system paths contain user input
- Capacitor plugins use unsanitized input
- Webview navigation uses user input

Common injection points:
- Webview content
- Native plugin handlers
- File system paths
- Capacitor plugin calls
- Webview navigation
"""

ATTACK_VECTOR = """
1. Webview injection:
   window.location = USER_INPUT;

2. Plugin injection:
   Capacitor.Plugins.FileSystem.readFile({
       path: USER_INPUT
   });

3. File path injection:
   Filesystem.readFile({
       path: USER_INPUT
   });

4. Plugin handler injection:
   // In native code:
   @PluginMethod()
   public void handler(String input) {
       webView.loadUrl("javascript:alert('" + input + "')");
   }

5. Navigation injection:
   Browser.open({ url: USER_INPUT });
"""

REMEDIATION = """
1. Sanitize all user input before rendering in webview
2. Validate native plugin handlers
3. Validate file system paths
4. Use Content Security Policy (CSP)
5. Escape HTML entities in user-controlled content
6. Audit all Capacitor plugins for user input
7. Validate webview navigation URLs
8. Use framework-safe methods for plugin communication
"""

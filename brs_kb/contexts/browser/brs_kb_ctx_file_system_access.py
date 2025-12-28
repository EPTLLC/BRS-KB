#!/usr/bin/env python3

"""
Project: BRS-KB (BRS XSS Knowledge Base)
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: 2025-12-26 UTC
Status: Created
Telegram: https://t.me/EasyProTech

Knowledge Base: File System Access API XSS
"""

DETAILS = {
    "title": "Cross-Site Scripting (XSS) via File System Access API",
    "severity": "critical",
    "cvss_score": 8.8,
    "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H",
    "reliability": "high",
    "cwe": ["CWE-79", "CWE-22"],
    "owasp": ["A03:2021", "A01:2021"],
    "tags": ["xss", "file-system", "native", "file-handle", "chrome-86", "critical"],
    "description": """
File System Access API (Chrome 86+) allows web apps to read/write files. XSS vulnerabilities
occur when user input controls file paths, file contents, or file handles without validation.

SEVERITY: CRITICAL
Direct file system access can lead to arbitrary file read/write, path traversal, and code execution.
""",
    "attack_vector": """
FILE SYSTEM PATH INJECTION:
const fileHandle = await window.showOpenFilePicker();
const file = await fileHandle.getFile();
const content = await file.text();
document.body.innerHTML = content;  // XSS if file contains HTML

FILE SYSTEM WRITE INJECTION:
const fileHandle = await window.showSaveFilePicker();
const writable = await fileHandle.createWritable();
await writable.write(userInput);  // XSS if written to HTML file

FILE SYSTEM DIRECTORY TRAVERSAL:
const dirHandle = await window.showDirectoryPicker();
const fileHandle = await dirHandle.getFileHandle('../sensitive.txt');  // Path traversal

FILE SYSTEM FILE NAME INJECTION:
const fileHandle = await window.showSaveFilePicker({
  suggestedName: userInput  // XSS if filename contains script
});

FILE SYSTEM READ INJECTION:
const [fileHandle] = await window.showOpenFilePicker();
const file = await fileHandle.getFile();
const text = await file.text();
eval(text);  // XSS if file contains JavaScript

FILE SYSTEM WRITE HTML:
const fileHandle = await window.showSaveFilePicker({
  types: [{
    description: 'HTML files',
    accept: { 'text/html': ['.html'] }
  }]
});
const writable = await fileHandle.createWritable();
await writable.write(`<script>${userInput}</script>`);  // XSS
""",
    "remediation": """
DEFENSE:

1. Validate all file paths (prevent directory traversal)
2. Sanitize file contents before rendering
3. Validate file types before processing
4. Use textContent instead of innerHTML
5. Implement strict file type whitelisting

SAFE PATTERN:
const fileHandle = await window.showOpenFilePicker();
const file = await fileHandle.getFile();

// Validate file type
if (!file.type.startsWith('text/')) {
  throw new Error('Invalid file type');
}

// Sanitize content
const content = await file.text();
element.textContent = content;  // Safe
// Or
element.innerHTML = DOMPurify.sanitize(content);

PATH VALIDATION:
function validatePath(path) {
  if (path.includes('..') || path.includes('/') || path.includes('\\')) {
    throw new Error('Invalid path');
  }
  return path;
}

OWASP REFERENCES:
- CWE-79: Cross-site Scripting
- CWE-22: Path Traversal
- File System Access API Specification
""",
}

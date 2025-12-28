#!/usr/bin/env python3
# Project: BRS-KB
# Company: EasyProTech LLC (www.easypro.tech)
# Dev: Brabus
# Date: 2025-12-27 UTC
# Status: Refactored
# Telegram: https://t.me/EasyProTech

"""
Web Worker XSS Context

XSS through Web Worker, SharedWorker, and Worklet injection.
"""

DETAILS = {
    "title": "Web Worker XSS",
    "severity": "high",
    "cvss_score": 7.2,
    "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
    "reliability": "high",
    "cwe": ["CWE-79"],
    "owasp": ["A03:2021"],
    "tags": ["worker", "webworker", "sharedworker", "worklet", "xss"],
    "description": """
Web Worker XSS occurs when attackers can inject code into Worker contexts.
Workers run in separate threads but can communicate with main thread via
postMessage, potentially exfiltrating data or performing malicious operations.
""",
    "attack_vector": """
WEB WORKER XSS VECTORS:

1. BLOB URL WORKER
   new Worker(URL.createObjectURL(new Blob([userCode])))

2. SHAREDWORKER INJECTION
   new SharedWorker(userUrl)

3. IMPORTSCRIPTS()
   In Worker: importScripts(userUrl)
   Loads and executes external script

4. WORKLET.ADDMODULE()
   CSS.paintWorklet.addModule(userUrl)

5. AUDIOWORKLET
   audioContext.audioWorklet.addModule(url)

6. PAINTWORKLET
   CSS.paintWorklet.addModule(url)

7. LAYOUTWORKLET
   CSS.layoutWorklet.addModule(url)

8. POSTMESSAGE DATA
   worker.postMessage(userPayload)
   Worker uses in eval/innerHTML

9. WORKER EVAL
   self.onmessage = e => eval(e.data)
""",
    "remediation": """
WEB WORKER XSS PREVENTION:

1. VALIDATE WORKER URLS
   Only create Workers from trusted URLs
   Check origin before new Worker()

2. CSP WORKER-SRC
   Content-Security-Policy: worker-src 'self'

3. SANITIZE POSTMESSAGE
   Validate message structure
   Never eval message data

4. AVOID EVAL IN WORKERS
   No eval/Function in message handlers

5. ORIGIN CHECKS
   self.onmessage = (e) => {
     if (e.origin !== expected) return
   }

6. RESTRICT IMPORTSCRIPTS
   Only import from same origin
   Use SRI for external scripts

7. VALIDATE WORKLET MODULES
   Check URL before addModule()
""",
}

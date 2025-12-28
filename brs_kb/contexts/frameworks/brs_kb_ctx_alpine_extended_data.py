#!/usr/bin/env python3

"""
Project: BRS-KB (BRS XSS Knowledge Base)
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: 2025-12-27 UTC
Status: Created
Telegram: https://t.me/EasyProTech

Alpine.js Extended Context - Data Module
"""

DESCRIPTION = """
Alpine.js provides declarative JavaScript via HTML attributes.
Extended vulnerabilities occur when user input is injected into Alpine.js
directives, expressions, or event handlers, allowing execution of arbitrary JavaScript.

Vulnerability occurs when:
- User-controlled data is injected into x-data expressions
- Alpine.js directives contain user input
- x-on event handlers use user input
- x-bind attributes are user-controlled
- Alpine.js expressions evaluate user input

Common injection points:
- x-data attribute expressions
- x-on:* event handlers
- x-bind:* attribute bindings
- x-text, x-html directives
- x-if, x-show conditional expressions
- Alpine.$data manipulation
"""

ATTACK_VECTOR = """
1. x-data injection:
   <div x-data="{value: USER_INPUT}">content</div>

2. x-on injection:
   <div x-on:click="USER_INPUT">Click</div>

3. x-html injection:
   <div x-html="USER_INPUT">content</div>

4. Expression injection:
   <div x-show="USER_INPUT">content</div>

5. x-bind injection:
   <div x-bind:onclick="USER_INPUT">content</div>

6. Alpine.$data injection:
   Alpine.$data(USER_INPUT)
"""

REMEDIATION = """
1. Sanitize all user input before using in Alpine directives
2. Never use x-html with user input
3. Validate Alpine expressions
4. Use Content Security Policy (CSP)
5. Escape HTML entities in user-controlled content
6. Validate x-data JSON structures
7. Audit all Alpine.js usage for user input
8. Use framework-safe methods for data binding
"""

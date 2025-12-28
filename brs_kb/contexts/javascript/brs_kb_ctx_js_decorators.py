#!/usr/bin/env python3

"""
Project: BRS-KB (BRS XSS Knowledge Base)
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: 2025-12-26 UTC
Status: Created
Telegram: https://t.me/EasyProTech

Knowledge Base: JavaScript Decorators XSS
"""

DETAILS = {
    "title": "Cross-Site Scripting (XSS) via JavaScript Decorators",
    "severity": "medium",
    "cvss_score": 6.8,
    "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:L/A:N",
    "reliability": "medium",
    "cwe": ["CWE-79"],
    "owasp": ["A03:2021"],
    "tags": ["xss", "decorators", "stage-3", "experimental", "typescript"],
    "description": """
JavaScript Decorators (Stage 3 proposal) allow modifying classes and methods. XSS vulnerabilities
occur when user input controls decorator definitions or decorator metadata without validation.

SEVERITY: MEDIUM
Experimental feature with growing adoption in TypeScript. Can lead to code injection if misused.
""",
    "attack_vector": """
DECORATOR DEFINITION INJECTION:
@${userInput}
class MyClass {
  // XSS if decorator name is controlled
}

DECORATOR METADATA INJECTION:
function decorator(value) {
  return function(target) {
    target.metadata = value;  // XSS if value is user-controlled
  };
}
@decorator(userInput)
class MyClass {}

DECORATOR WITH EVAL:
function decorator(code) {
  return function(target) {
    eval(code);  // XSS if code is user-controlled
  };
}
@decorator(userInput)
class MyClass {}

DECORATOR PROPERTY INJECTION:
class MyClass {
  @decorator(userInput)
  property = 'value';  // XSS if decorator processes userInput
}

DECORATOR METHOD INJECTION:
class MyClass {
  @decorator(userInput)
  method() {
    // XSS if decorator processes userInput
  }
}
""",
    "remediation": """
DEFENSE:

1. Validate decorator names and definitions
2. Sanitize decorator metadata
3. Avoid eval() in decorators
4. Use whitelist for allowed decorators
5. Implement input validation

SAFE PATTERN:
const allowedDecorators = ['validate', 'sanitize', 'log'];
function createDecorator(name) {
  if (!allowedDecorators.includes(name)) {
    throw new Error('Decorator not allowed');
  }
  return function(target) {
    // Safe decorator logic
  };
}
@createDecorator(userInput)
class MyClass {}

METADATA SANITIZATION:
function decorator(value) {
  return function(target) {
    target.metadata = DOMPurify.sanitize(value);
  };
}

OWASP REFERENCES:
- CWE-79: Cross-site Scripting
- Decorators Proposal (Stage 3)
""",
}

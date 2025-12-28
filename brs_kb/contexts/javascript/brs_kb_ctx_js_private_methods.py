#!/usr/bin/env python3

"""
Project: BRS-KB (BRS XSS Knowledge Base)
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: 2025-12-26 UTC
Status: Created
Telegram: https://t.me/EasyProTech

Knowledge Base: Private Methods/Fields XSS
"""

DETAILS = {
    "title": "Cross-Site Scripting (XSS) via Private Methods/Fields",
    "severity": "medium",
    "cvss_score": 6.8,
    "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:L/A:N",
    "reliability": "high",
    "cwe": ["CWE-79"],
    "owasp": ["A03:2021"],
    "tags": ["xss", "private", "class-fields", "encapsulation", "es2022"],
    "description": """
Private methods and fields (ES2022) provide encapsulation. XSS vulnerabilities occur when
user input controls private field values or private method execution without validation.

SEVERITY: MEDIUM
Encapsulation can be bypassed if private fields contain user-controlled data that is later rendered.
""",
    "attack_vector": """
PRIVATE FIELD INJECTION:
class MyClass {
  #data = userInput;  // XSS if #data is rendered
  getData() {
    return this.#data;
  }
}
const instance = new MyClass();
element.innerHTML = instance.getData();  // XSS

PRIVATE METHOD INJECTION:
class MyClass {
  #process(data) {
    return data;  // XSS if data is user-controlled
  }
  publicMethod(input) {
    return this.#process(input);
  }
}
const instance = new MyClass();
element.innerHTML = instance.publicMethod(userInput);  // XSS

PRIVATE STATIC FIELD:
class MyClass {
  static #config = userInput;  // XSS if config is rendered
}
element.innerHTML = MyClass.getConfig();  // XSS

PRIVATE FIELD WITH EVAL:
class MyClass {
  #code = userInput;
  execute() {
    eval(this.#code);  // XSS
  }
}

PRIVATE FIELD INNERHTML:
class MyClass {
  #html = userInput;
  render() {
    element.innerHTML = this.#html;  // XSS
  }
}
""",
    "remediation": """
DEFENSE:

1. Sanitize data before storing in private fields
2. Sanitize data before returning from private methods
3. Use textContent instead of innerHTML
4. Validate private field values
5. Implement input validation

SAFE PATTERN:
class MyClass {
  #data = '';
  constructor(input) {
    this.#data = DOMPurify.sanitize(input);  // Sanitize on input
  }
  getData() {
    return this.#data;  // Safe
  }
  render() {
    element.textContent = this.#data;  // Safe
  }
}

VALIDATION:
class MyClass {
  #data = '';
  setData(input) {
    if (input.length > 1000) {
      throw new Error('Input too long');
    }
    this.#data = DOMPurify.sanitize(input);
  }
}

OWASP REFERENCES:
- CWE-79: Cross-site Scripting
- ES2022 Private Fields Specification
""",
}

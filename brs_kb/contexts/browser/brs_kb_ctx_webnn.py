#!/usr/bin/env python3

"""
Project: BRS-KB (BRS XSS Knowledge Base)
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: 2025-12-26 UTC
Status: Created
Telegram: https://t.me/EasyProTech

Knowledge Base: Web Neural Network API XSS
"""

DETAILS = {
    "title": "Cross-Site Scripting (XSS) via Web Neural Network API",
    "severity": "medium",
    "cvss_score": 6.8,
    "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:L/A:N",
    "reliability": "low",
    "cwe": ["CWE-79"],
    "owasp": ["A03:2021"],
    "tags": ["xss", "webnn", "ml", "ai", "experimental", "chrome-121"],
    "description": """
Web Neural Network API (Chrome 121+, experimental) provides ML inference. XSS vulnerabilities
occur when user input controls model inputs, outputs, or execution without validation.

SEVERITY: MEDIUM
Experimental API with limited adoption. Can lead to XSS if model outputs are rendered unsafely.
""",
    "attack_vector": """
WEBNN INPUT INJECTION:
const context = await navigator.ml.createContext();
const builder = new MLGraphBuilder(context);
const input = builder.input('input', { type: 'float32', dimensions: [1, userInput] });  // XSS if dimensions are controlled

WEBNN OUTPUT INJECTION:
const results = await graph.compute({ input: new Float32Array(userInput) });
const output = results.output;
element.innerHTML = output.toString();  // XSS if output is rendered

WEBNN MODEL INJECTION:
const model = await navigator.ml.createModel(userInput);  // XSS if model URL is data:

WEBNN OPERATION INJECTION:
const op = builder.${userInput}(input);  // XSS if operation name is controlled

WEBNN TENSOR DATA:
const tensor = new MLTensor({ type: 'float32', dimensions: [1, 1], data: userInput });
const result = await graph.compute({ input: tensor });
""",
    "remediation": """
DEFENSE:

1. Validate all model inputs
2. Sanitize model outputs before rendering
3. Validate model URLs (whitelist HTTPS only)
4. Validate operation names
5. Implement input validation

SAFE PATTERN:
function validateDimensions(dims) {
  const maxSize = 1000;
  if (dims.some(d => d > maxSize)) {
    throw new Error('Dimensions too large');
  }
  return dims;
}
const input = builder.input('input', {
  type: 'float32',
  dimensions: validateDimensions([1, userInput])
});

OUTPUT SANITIZATION:
const results = await graph.compute({ input: tensor });
element.textContent = results.output.toString();  // Safe
// Or
element.innerHTML = DOMPurify.sanitize(results.output.toString());

OWASP REFERENCES:
- CWE-79: Cross-site Scripting
- Web Neural Network API Specification
""",
}

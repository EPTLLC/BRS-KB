# Contributing to BRS-KB

Thank you for your interest in contributing to BRS-KB! This is a community-driven project, and we welcome contributions from security researchers, developers, and enthusiasts worldwide.

## Table of Contents

- [How to Contribute](#how-to-contribute)
- [Adding New XSS Contexts](#adding-new-xss-contexts)
- [Updating Existing Contexts](#updating-existing-contexts)
- [Code Style Guidelines](#code-style-guidelines)
- [Testing](#testing)
- [Pull Request Process](#pull-request-process)
- [Community Guidelines](#community-guidelines)

## How to Contribute

There are many ways to contribute to BRS-KB:

1. **Add new XSS vectors** - Share your knowledge about new attack techniques
2. **Update existing contexts** - Keep information current with latest bypasses
3. **Improve documentation** - Help make the knowledge base more accessible
4. **Report issues** - Found outdated info or errors? Let us know
5. **Share examples** - Add real-world attack examples and POCs
6. **Improve code** - Enhance the loader, API, or tooling

## Adding New XSS Contexts

### Step 1: Create a New Module

Create a new Python file in `brs_kb/contexts/` directory:

```bash
touch brs_kb/contexts/your_new_context.py
```

### Step 2: Follow the Template

```python
#!/usr/bin/env python3

"""
Project: BRS-KB (BRS XSS Knowledge Base)
Company: EasyProTech LLC (www.easypro.tech)
Dev: YourName
Date: YYYY-MM-DD HH:MM:SS TZ
Status: Created
Telegram: https://t.me/easyprotech

Knowledge Base: Your Context Name
"""

DETAILS = {
    "title": "Cross-Site Scripting in Your Context",
    
    # Metadata (highly recommended)
    "severity": "high",  # low, medium, high, critical
    "cvss_score": 7.5,   # 0.0 to 10.0
    "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:N",
    "reliability": "firm",  # tentative, firm, certain
    "cwe": ["CWE-79"],
    "owasp": ["A03:2021"],
    "tags": ["xss", "your-context", "custom-tag"],
    
    # Required fields
    "description": """
Detailed explanation of the vulnerability context.

Include:
- What makes this context vulnerable
- Common scenarios where it appears
- Why it's dangerous
- Real-world impact

Minimum 50 characters.
""",

    "attack_vector": """
ATTACK TECHNIQUES:

1. BASIC ATTACKS:
   <your payload examples>
   
2. ADVANCED BYPASSES:
   <bypass techniques>
   
3. FRAMEWORK-SPECIFIC:
   <framework-related vectors>

Include real, working payloads with explanations.
Minimum 50 characters.
""",

    "remediation": """
SECURITY MEASURES:

1. PRIMARY DEFENSE:
   - Step-by-step remediation
   - Code examples
   
2. DEFENSE IN DEPTH:
   - Additional security layers
   - Best practices
   
3. TESTING:
   - How to verify the fix
   
Include practical, actionable advice.
Minimum 50 characters.
""",

    # Optional: Add practical examples
    "examples": [
        {
            "name": "Basic Attack Example",
            "payload": "<your payload>",
            "poc_url": "https://example.com/?param=<payload>",
            "screenshot": "path/to/screenshot.png"  # optional
        }
    ]
}
```

### Step 3: Validate Your Module

Run validation to ensure your module meets the schema:

```bash
pytest tests/test_knowledge_base.py -k "test_schema_validation"
```

### Step 4: Test Integration

```python
from brs_kb import get_vulnerability_details

details = get_vulnerability_details('your_new_context')
print(details['title'])
```

## Updating Existing Contexts

When updating existing context modules:

1. **Add new attack vectors** - Share new techniques you've discovered
2. **Update bypass methods** - Keep defenses current
3. **Improve clarity** - Make explanations more understandable
4. **Add examples** - Real-world examples are valuable
5. **Update metadata** - Keep CVSS scores and CWE mappings accurate

**Important**: Always increment the version in comments and update the date.

## Code Style Guidelines

### Language
- **All content must be in English** - This is a global project
- Use clear, professional language
- Avoid slang or regional expressions

### Python Code
- Follow PEP 8 style guide
- Use meaningful variable names
- Keep lines under 100 characters
- Add comments for complex logic

### File Headers
Every file must include:

```python
"""
Project: BRS-KB (BRS XSS Knowledge Base)
Company: EasyProTech LLC (www.easypro.tech)
Dev: YourName
Date: YYYY-MM-DD HH:MM:SS TZ
Status: Created/Modified
Telegram: https://t.me/easyprotech
"""
```

### Content Guidelines
- Be accurate and precise
- Provide working, tested payloads
- Include references to sources
- Cite CVEs when applicable
- Add framework versions when relevant

## Testing

Before submitting your contribution:

```bash
# Run all tests
pytest tests/ -v

# Run specific tests
pytest tests/test_knowledge_base.py -v

# Check code style
black --check brs_kb/
pylint brs_kb/

# Type checking
mypy brs_kb/
```

If tests don't exist yet, that's okay - the project is growing!

## Pull Request Process

1. **Fork the repository**
   ```bash
   git clone https://github.com/YOUR-USERNAME/BRS-KB.git
   ```

2. **Create a feature branch**
   ```bash
   git checkout -b feature/your-feature-name
   ```

3. **Make your changes**
   - Add or update context modules
   - Follow coding guidelines
   - Test your changes

4. **Commit your changes**
   ```bash
   git add .
   git commit -m "Add: Description of your contribution"
   ```
   
   Use meaningful commit messages:
   - `Add: New context for WebRTC XSS`
   - `Update: HTML attribute context with new bypasses`
   - `Fix: Typo in JavaScript context description`
   - `Improve: Documentation for reverse mapping`

5. **Push to your fork**
   ```bash
   git push origin feature/your-feature-name
   ```

6. **Open a Pull Request**
   - Provide a clear description
   - Reference any related issues
   - Explain what you've added/changed
   - List any breaking changes

7. **Wait for review**
   - Maintainers will review your PR
   - Be responsive to feedback
   - Make requested changes if needed

## Community Guidelines

### Be Respectful
- Treat all contributors with respect
- Be constructive in feedback
- Welcome newcomers
- Help others learn

### Share Knowledge
- Explain your techniques
- Provide context for your contributions
- Share sources and references
- Help others understand XSS better

### Stay Professional
- No offensive content
- No malicious code
- No personal attacks
- Keep discussions technical

### Give Credit
- Cite sources when using others' research
- Credit original researchers
- Link to relevant CVEs and advisories
- Acknowledge collaborators

## Questions?

- **GitHub Issues**: For bugs and feature requests
- **GitHub Discussions**: For questions and general discussion
- **Telegram**: https://t.me/easyprotech
- **Email**: contact@easypro.tech

## License

By contributing to BRS-KB, you agree that your contributions will be licensed under the MIT License.

---

**Thank you for making BRS-KB better for the security community!**

*Open Knowledge for Security Community*


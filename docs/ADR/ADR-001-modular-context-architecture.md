# ADR-001: Modular Context Architecture

**Status:** Accepted  
**Date:** 2025-10-25  
**Deciders:** Brabus / EasyProTech LLC

## Context

Original context files were large (400-700 lines), making them:
- Difficult to maintain and review
- Hard to navigate
- Violating single responsibility principle
- Exceeding recommended file size limits (< 300 lines)

## Decision

Split large context files into smaller, modular components:

1. **Main context file** (`*_context.py`): Contains only the DETAILS dictionary (< 50 lines)
2. **Data file** (`*_data.py`): Contains DESCRIPTION and REMEDIATION strings
3. **Attack vectors file** (`*_attack_vectors.py`): Contains ATTACK_VECTOR string

**Example Structure:**
```
html_content.py (30 lines)
    ├── html_content_data.py (DESCRIPTION, REMEDIATION)
    └── html_content_attack_vectors.py (ATTACK_VECTOR)
```

## Consequences

### Positive
- ✅ Easier to maintain and review
- ✅ Better code organization
- ✅ Faster code reviews
- ✅ Follows single responsibility principle
- ✅ Files comply with < 300 lines guideline
- ✅ Easier to locate specific content

### Negative
- ⚠️ More files to manage (3x files per context)
- ⚠️ Slightly more complex imports
- ⚠️ Need to ensure consistency across files

### Mitigation
- Use clear naming conventions
- Document import structure
- Add validation to ensure all required data is present

## Implementation

Refactored 18 large context files:
- html_content.py: 404 → 30 lines
- css_context.py: 680 → 31 line
- javascript_context.py: 641 → 31 line
- graphql_xss.py: 638 → 31 line
- And 14 more contexts...

## References

- [ARCHITECTURE.md](../ARCHITECTURE.md#context-system)



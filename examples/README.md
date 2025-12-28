# BRS-KB Examples

This directory contains practical examples demonstrating how to integrate and use BRS-KB in various scenarios.

## Available Examples

### 1. Basic Usage (`basic_usage.py`)

Demonstrates fundamental BRS-KB functionality:
- Getting knowledge base information
- Listing available contexts
- Retrieving vulnerability details
- Working with metadata (severity, CVSS, CWE)

**Run:**
```bash
python3 examples/basic_usage.py
```

### 2. Scanner Integration (`scanner_integration.py`)

Shows how to integrate BRS-KB into a security scanner:
- Creating a scanner class
- Detecting vulnerability contexts
- Enriching findings with KB data
- Generating comprehensive reports

**Use Case:** XSS scanners, web application security tools, automated testing frameworks

**Run:**
```bash
python3 examples/scanner_integration.py
```

### 3. SIEM Integration (`siem_integration.py`)

Demonstrates SIEM/SOC integration for threat intelligence:
- Creating security events
- Enriching with KB metadata
- Calculating threat levels and priorities
- Building SOC dashboards
- Exporting to JSON for ingestion

**Use Case:** SIEM systems, SOC operations, security monitoring, threat intelligence platforms

**Run:**
```bash
python3 examples/siem_integration.py
```

### 4. Reverse Mapping (`reverse_mapping.py`)

Shows payload-to-defense mapping capabilities:
- Finding contexts for specific payloads
- Getting recommended defenses for contexts
- Retrieving defense implementation details
- Building comprehensive defense strategies

**Use Case:** Security architecture, defense planning, remediation guidance

**Run:**
```bash
python3 examples/reverse_mapping.py
```

## Integration Patterns

### Pattern 1: Simple Lookup

```python
from brs_kb import get_vulnerability_details

details = get_vulnerability_details('html_content')
print(details['title'])
print(details['severity'])
```

### Pattern 2: Context Detection + Enrichment

```python
from brs_kb import get_vulnerability_details

def enrich_finding(context_type, url, payload):
 kb_data = get_vulnerability_details(context_type)
 
 return {
 'url': url,
 'payload': payload,
 'title': kb_data['title'],
 'severity': kb_data['severity'],
 'cvss': kb_data['cvss_score'],
 'remediation': kb_data['remediation']
 }
```

### Pattern 3: Defense Strategy Builder

```python
from brs_kb.reverse_map import get_defenses_for_context

contexts = ['html_content', 'javascript', 'css']
all_defenses = []

for context in contexts:
 defenses = get_defenses_for_context(context)
 all_defenses.extend(defenses)

# Prioritize and implement defenses
critical = [d for d in all_defenses if d['required']]
```

## Custom Integration Ideas

### 1. Bug Bounty Helper
Create a tool that:
- Analyzes discovered XSS
- Provides context-specific information
- Suggests testing payloads
- Generates professional reports

### 2. Training Platform
Build an educational tool that:
- Teaches XSS vulnerability types
- Provides interactive examples
- Quizzes students on contexts
- Tracks learning progress

### 3. CI/CD Security Gate
Implement automated checks that:
- Scan code for XSS patterns
- Classify vulnerability contexts
- Calculate risk scores
- Block deployments based on severity

### 4. API Wrapper Service
Create a REST API that:
- Exposes KB data via HTTP
- Provides search functionality
- Serves as microservice
- Integrates with other tools

### 5. Browser Extension
Develop an extension that:
- Analyzes web pages for XSS
- Identifies vulnerability contexts
- Shows KB information inline
- Helps security researchers

## Testing Your Integration

After implementing your integration:

1. **Functional Testing**
 ```python
 from brs_kb import list_contexts
 assert len(list_contexts()) > 0
 ```

2. **Data Validation**
 ```python
 from brs_kb import get_vulnerability_details
 details = get_vulnerability_details('html_content')
 assert 'title' in details
 assert 'severity' in details
 ```

3. **Error Handling**
 ```python
 # Should gracefully handle unknown contexts
 details = get_vulnerability_details('unknown_context')
 assert details is not None
 ```

## Performance Considerations

BRS-KB is designed for efficiency:
- **Lazy Loading**: Contexts loaded on first use
- **Caching**: Loaded contexts cached in memory
- **Zero Dependencies**: No external dependencies
- **Fast Lookups**: Dictionary-based lookups (O(1))

For high-performance applications:
```python
from brs_kb import get_all_contexts

# Pre-load all contexts once
all_contexts = get_all_contexts()

# Use cached data
for context_name, details in all_contexts.items():
 process(details)
```

## Contributing Examples

Have a integration example? Share it!

1. Create your example file
2. Add clear comments and documentation
3. Test thoroughly
4. Submit a pull request

See [CONTRIBUTING.md](../CONTRIBUTING.md) for details.

## Support

- **GitHub Issues**: Report problems or request features
- **GitHub Discussions**: Ask questions and share ideas
- **Telegram**: https://t.me/easyprotech

## License

All examples are provided under MIT License.
Free to use, modify, and integrate into your projects.

---

**BRS-KB**: Open Knowledge for Security Community


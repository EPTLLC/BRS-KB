# BRS-KB Security Scanner Plugins

This directory contains plugins and integrations for popular security testing tools to enhance XSS vulnerability detection using BRS-KB (BRS XSS Knowledge Base).

## Available Plugins

### Burp Suite Plugin (`burp_suite/`)
**BRSKBExtension.java** - Java extension for Burp Suite Professional

**Features:**
- Real-time XSS payload analysis during proxying
- Automatic context detection for intercepted requests
- Payload effectiveness testing
- Context-specific vulnerability reporting
- Integration with BRS-KB's 27 XSS contexts

**Installation:**
1. Download and install Burp Suite Professional
2. Go to Extender → Extensions → Add
3. Select the `BRSKBExtension.java` file
4. Enable the extension

**Usage:**
- Intercept HTTP requests in Proxy tab
- Right-click → "Analyze with BRS-KB"
- View analysis results in the BRS-KB tab
- Test payloads with the built-in tester

### OWASP ZAP Plugin (`owasp_zap/`)
**brs_kb_zap.py** - Python integration script for OWASP ZAP

**Features:**
- Automated XSS scanning with BRS-KB intelligence
- Context-aware payload injection
- WAF bypass technique detection
- Comprehensive vulnerability reporting
- Integration with ZAP's active scanning

**Installation:**
1. Install OWASP ZAP
2. Place `brs_kb_zap.py` in ZAP scripts directory
3. Load the script in ZAP's Scripts tab
4. Enable for active scanning

**Usage:**
```python
from brs_kb_zap import BRSKBZAPIntegration
integration = BRSKBZAPIntegration()
results = integration.analyze_request("request_id")
print(integration.generate_report(results))
```

### Nuclei Templates (`nuclei/templates/`)
**brs-kb-xss.yaml** - YAML templates for Nuclei security scanner

**Features:**
- 200+ categorized XSS payloads
- Context-specific testing (27 XSS contexts)
- WAF bypass technique detection
- Modern web technology testing
- Comprehensive workflow templates

**Installation:**
1. Install Nuclei security scanner
2. Place templates in Nuclei templates directory
3. Run with: `nuclei -t brs-kb-xss.yaml -u target.com`

**Available Templates:**
- `brs-kb-xss.yaml` - Basic XSS detection
- `brs-kb-context-specific.yaml` - Context-specific testing
- `brs-kb-websocket-xss.yaml` - WebSocket XSS testing
- `brs-kb-modern-web-xss.yaml` - Modern web technologies
- `brs-kb-waf-bypass.yaml` - WAF bypass techniques
- `brs-kb-comprehensive-xss.yaml` - Complete workflow

**Usage Examples:**
```bash
# Basic XSS scanning
nuclei -t plugins/nuclei/templates/brs-kb-xss.yaml -u https://example.com

# Context-specific testing
nuclei -t plugins/nuclei/templates/brs-kb-context-specific.yaml -u https://example.com

# Complete workflow
nuclei -t plugins/nuclei/templates/brs-kb-complete-workflow.yaml -u https://example.com

# Export results
nuclei -t plugins/nuclei/templates/brs-kb-xss.yaml -u https://example.com -o results.json
```

### Postman Collection (`postman/`)
**BRSKB Postman Collection** - Comprehensive API testing collection for BRS-KB

**Features:**
- 9 API endpoints for complete BRS-KB functionality
- Automated testing with response validation
- Pre-request and test scripts for BRS-KB integration
- Environment variables and authentication
- Professional API testing workflows

**Installation:** Import `plugins/postman/brs_kb_postman_collection.json` in Postman

**Usage Examples:**
```bash
# Test BRS-KB API endpoints
# Import collection in Postman
# Run requests to test functionality
# Validate responses with built-in tests
```

### Insomnia Plugin (`insomnia/`)
**BRSKB Insomnia Plugin** - JavaScript plugin for Insomnia REST Client

**Features:**
- Real-time request analysis during API testing
- Context-aware payload suggestions
- Vulnerability detection in API responses
- Custom request hooks and validation
- Professional security testing interface

**Installation:** Load `plugins/insomnia/brs_kb_insomnia_plugin.js` in Insomnia scripts

**Usage Examples:**
```javascript
// Use in Insomnia test scripts
const BRSKBPlugin = require('./brs_kb_insomnia_plugin');
const analysis = BRSKBPlugin.analyzeRequest(pm.request);
console.log('BRS-KB Analysis:', analysis);
```

### Browser Extension (`browser_extension/`)
**BRSKB Browser Extension** - Chrome/Firefox extension for real-time XSS detection

**Features:**
- Real-time input field analysis in web pages
- Visual indicators for potentially vulnerable elements
- Context detection for different XSS types
- Payload suggestions based on detected patterns
- Professional security research interface

**Installation:** Load unpacked extension from `browser_extension/` directory

**Usage Examples:**
```bash
# Load extension in browser
# Navigate to any website with forms
# Look for red indicators next to inputs
# Click extension icon for detailed analysis
# Use context menu on selected text
```

## Integration Benefits

### Enhanced Detection
- **27 XSS contexts** vs traditional 5-7
- **200+ payloads** with automatic context detection
- **WAF bypass techniques** included
- **Modern web technologies** coverage

### Intelligence-Driven Testing
- **Context-aware** payload selection
- **Confidence scoring** for findings
- **Risk assessment** with CVSS scores
- **Framework-specific** guidance

### Professional Workflows
- **CI/CD integration** ready
- **Report generation** for compliance
- **Export capabilities** for other tools
- **Team collaboration** features

## Quick Start

### 1. Install Dependencies
```bash
# Burp Suite - Download from PortSwigger
# OWASP ZAP - Download from OWASP
# Nuclei - Install from projectnuclei.io
# BRS-KB - pip install brs-kb
```

### 2. Deploy Plugins
```bash
# Copy plugin files to respective tool directories
cp plugins/burp_suite/BRSKBExtension.java /path/to/burp/extensions/
cp plugins/owasp_zap/brs_kb_zap.py /path/to/zap/scripts/
cp plugins/nuclei/templates/* /path/to/nuclei/templates/
```

### 3. Configure Tools
- **Burp Suite**: Enable extension in Extender tab
- **OWASP ZAP**: Load script and enable for scanning
- **Nuclei**: Templates are ready to use

### 4. Start Scanning
```bash
# Example Nuclei scan
nuclei -t plugins/nuclei/templates/brs-kb-complete-workflow.yaml \
 -u https://target.com \
 -severity high \
 -o brs-kb-results.txt
```

## Advanced Usage

### Custom Configuration
Each plugin can be customized for specific environments:

```yaml
# Nuclei custom config
custom-templates:
 - id: brs-kb-custom
 # Custom payload sets
 # Context-specific rules
 # Organization-specific reporting
```

### Integration with CI/CD
```yaml
# GitHub Actions example
- name: BRS-KB Security Scan
 run: |
 nuclei -t plugins/nuclei/templates/ -u ${{ env.TARGET_URL }}
 brs-kb generate-report > security-report.md
```

### Report Generation
```bash
# Generate comprehensive security report
brs-kb generate-report > security-assessment-$(date +%Y%m%d).md

# Export for compliance
brs-kb export contexts --format json --output compliance-data.json
```

## Troubleshooting

### Common Issues

**Burp Suite Extension Not Loading:**
- Ensure Java 8+ is installed
- Check file permissions
- Verify extension is enabled in Extender

**OWASP ZAP Script Errors:**
- Install required Python packages
- Check ZAP Python API availability
- Verify script permissions

**Nuclei Templates Not Found:**
- Check template directory path
- Ensure YAML syntax is valid
- Verify Nuclei version compatibility

### Support

For plugin-specific issues:
- **Burp Suite**: Check PortSwigger community forums
- **OWASP ZAP**: ZAP User Group on OWASP
- **Nuclei**: Project Nuclei GitHub issues

For BRS-KB integration issues:
- Check GitHub Issues: https://github.com/EPTLLC/BRS-KB/issues
- Contact: https://t.me/easyprotech

## Version Compatibility

| Plugin | BRS-KB Version | Tool Version | Status |
|--------|---------------|--------------|---------|
| Burp Suite | 2.0.0+ | 2023.1+ | Active |
| OWASP ZAP | 2.0.0+ | 2.12+ | Active |
| Nuclei | 2.0.0+ | 2.8+ | Active |
| Postman | 2.0.0+ | 10.0+ | Active |
| Insomnia | 2.0.0+ | 2023.1+ | Active |
| Browser Extension | 2.0.0+ | Chrome 88+ | Active |
| Splunk | 2.0.0+ | 8.0+ | Active |
| Elasticsearch | 2.0.0+ | 7.10+ | Active |
| Graylog | 2.0.0+ | 4.0+ | Active |

## Contributing

To contribute new plugins or improve existing ones:

1. Fork the repository
2. Create feature branch
3. Add plugin code
4. Update documentation
5. Submit pull request

## License

All plugins are released under the MIT License, same as BRS-KB.

---

**Made with by EasyProTech LLC** 
**BRS-KB: Professional XSS Intelligence Platform**

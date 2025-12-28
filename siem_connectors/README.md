# BRS-KB SIEM Connectors

SIEM connectors for integrating BRS-KB XSS vulnerability data with monitoring and alerting platforms.

## Available Connectors

### Splunk Integration (`splunk/`)
**BRSKB Splunk App** - Splunk application for BRS-KB data ingestion and alerting

**Features:**
- Real-time XSS vulnerability data ingestion
- Custom dashboards for XSS context analysis
- Alerting rules for critical vulnerabilities
- Correlation with existing security events
- Historical trend analysis

**Installation:**
1. Install Splunk Enterprise or Splunk Cloud
2. Copy `siem_connectors/splunk/brs_kb_app.tar.gz` to Splunk apps directory
3. Restart Splunk
4. Configure BRS-KB API endpoint in app settings

**Usage:**
```bash
# Send vulnerability data to Splunk
python3 siem_connectors/splunk/brs_kb_splunk_connector.py --api-key YOUR_API_KEY --splunk-url https://your-splunk.com:8088 --index brs_kb
```

### Elasticsearch Integration (`elastic/`)
**BRSKB Elasticsearch Integration** - Logstash/Beats integration for BRS-KB data

**Features:**
- Real-time log ingestion via Logstash
- Kibana dashboards for XSS analysis
- Machine learning anomaly detection
- Correlation with SIEM data
- Alerting via Elasticsearch Watcher

**Installation:**
1. Install Elasticsearch and Kibana
2. Deploy Logstash configuration
3. Configure BRS-KB data source

**Usage:**
```bash
# Send data to Elasticsearch
python3 siem_connectors/elastic/brs_kb_elastic_connector.py --es-url https://your-elastic.com:9200 --index brs_kb_xss
```

### Graylog Integration (`graylog/`)
**BRSKB Graylog Plugin** - Graylog content pack for BRS-KB data integration

**Features:**
- Real-time log ingestion via GELF
- Custom dashboards and widgets
- Alerting rules and notifications
- Search and correlation capabilities
- Stream processing for XSS events

**Installation:**
1. Install Graylog
2. Import content pack
3. Configure BRS-KB data source

**Usage:**
```bash
# Send data to Graylog
python3 siem_connectors/graylog/brs_kb_graylog_connector.py --graylog-url https://your-graylog.com:12201/gelf
```

## Integration Features

### Data Ingestion
- **Real-time processing** of XSS vulnerability findings
- **Structured data** with CVSS scores, context information, and metadata
- **Historical tracking** of vulnerability trends
- **Correlation** with existing security events

### Alerting & Monitoring
- **Critical vulnerability alerts** based on CVSS scores
- **Context-specific notifications** for different XSS types
- **Trend analysis** for vulnerability patterns
- **Automated response** triggers

### Dashboards & Visualization
- **XSS context distribution** charts
- **Vulnerability severity** heatmaps
- **Time-based trends** for attack patterns
- **Geographic distribution** of findings
- **Top affected applications** analysis

### Reporting & Compliance
- **Executive summaries** for management
- **Technical reports** for security teams
- **Compliance mapping** to standards
- **Audit trails** for regulatory requirements

## Quick Start

### 1. Install SIEM System
```bash
# Splunk
wget -O splunk.deb https://download.splunk.com/products/splunk/releases/.../splunk.deb

# Elasticsearch
# Follow official installation guide

# Graylog
# Follow official installation guide
```

### 2. Deploy BRS-KB Connectors
```bash
# Copy connector files
cp siem_connectors/splunk/brs_kb_app.tar.gz /opt/splunk/etc/apps/
cp siem_connectors/elastic/logstash.conf /etc/logstash/conf.d/
cp siem_connectors/graylog/content-pack.json /opt/graylog/data/contentpacks/
```

### 3. Configure Data Sources
```python
# Example configuration
from siem_connectors.splunk.brs_kb_splunk_connector import BRSKBSplunkConnector

connector = BRSKBSplunkConnector(
 api_key="your_brs_kb_api_key",
 splunk_url="https://your-splunk.com:8088",
 index="brs_kb_security"
)

# Send vulnerability data
connector.send_vulnerability_data(vulnerability_id="xss_001", context="html_content")
```

### 4. Set Up Dashboards
- Import provided dashboard configurations
- Customize for your environment
- Set up alerting rules
- Configure notifications

## Data Format

### Common Event Format
```json
{
 "timestamp": "2025-10-25T12:00:00Z",
 "event_type": "xss_vulnerability_detected",
 "source": "brs_kb",
 "severity": "high",
 "cvss_score": 7.5,
 "context": "websocket_xss",
 "payload": "<script>alert(1)</script>",
 "description": "WebSocket XSS vulnerability detected",
 "metadata": {
 "confidence": 0.95,
 "browser_support": ["chrome", "firefox"],
 "waf_evasion": false,
 "tags": ["websocket", "realtime"]
 },
 "recommendations": [
 "Implement Content Security Policy (CSP)",
 "Validate WebSocket message content"
 ]
}
```

### Alert Format
```json
{
 "alert_id": "brs_kb_critical_xss_001",
 "timestamp": "2025-10-25T12:00:00Z",
 "severity": "critical",
 "title": "Critical XSS Vulnerability Detected",
 "description": "WebSocket XSS with CVSS 7.5 detected in application",
 "context": "websocket_xss",
 "cvss_score": 7.5,
 "affected_systems": ["web_application"],
 "immediate_actions": [
 "Block malicious WebSocket connections",
 "Implement input sanitization",
 "Deploy CSP headers"
 ]
}
```

## Monitoring & Alerting

### Critical Alerts
- **CVSS Score ≥ 7.0** - Immediate security team notification
- **Multiple contexts** - Potential sophisticated attack
- **WAF bypass** - Advanced persistent threat indicator
- **New context discovery** - Emerging attack vectors

### Trend Monitoring
- **Context frequency** - Most common XSS types
- **Severity distribution** - Critical vs high vs medium
- **Browser targeting** - Platform-specific attacks
- **Geographic patterns** - Regional attack trends

### Automated Responses
- **Automatic blocking** of malicious IPs
- **Dynamic WAF rule updates**
- **Security team escalation**
- **Incident response triggers**

## Troubleshooting

### Common Issues

**Splunk Integration:**
- Check API key permissions
- Verify index exists and is writable
- Monitor Splunk ingestion pipeline

**Elasticsearch Integration:**
- Verify cluster health
- Check Logstash configuration
- Monitor data ingestion rate

**Graylog Integration:**
- Verify GELF endpoint connectivity
- Check content pack import
- Monitor stream processing

### Debug Mode
```python
# Enable debug logging
import logging
logging.basicConfig(level=logging.DEBUG)

# Test connection
connector.test_connection()
```

### Support

For SIEM-specific issues:
- **Splunk**: Splunk community forums and documentation
- **Elasticsearch**: Elastic discuss forums
- **Graylog**: Graylog community

For BRS-KB integration issues:
- Check GitHub Issues: https://github.com/EPTLLC/BRS-KB/issues
- Contact: https://t.me/easyprotech

## Version Compatibility

| SIEM System | BRS-KB Version | Minimum Version | Status |
|-------------|---------------|----------------|---------|
| Splunk | 2.0.0+ | 8.0+ | Active |
| Elasticsearch | 2.0.0+ | 7.10+ | Active |
| Graylog | 2.0.0+ | 4.0+ | Active |

## Contributing

To contribute new SIEM connectors or improve existing ones:

1. Fork the repository
2. Create feature branch
3. Add connector implementation
4. Update documentation
5. Submit pull request

## License

All SIEM connectors are released under the MIT License, same as BRS-KB.

---

**Made with by EasyProTech LLC** 
**BRS-KB: Professional XSS Intelligence Platform**

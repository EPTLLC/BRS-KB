#!/usr/bin/env python3

"""
Project: BRS-KB (BRS XSS Knowledge Base)
Company: EasyProTech LLC (www.easyprotech)
Dev: Brabus
Date: Sat 25 Oct 2025 12:00:00 UTC
Status: Enhanced
Telegram: https://t.me/easyprotech

Example: BRS-KB SIEM Integration - Enterprise Security Monitoring
Demonstrates integration with Splunk, Elasticsearch, and Graylog SIEM systems
"""

import json
from brs_kb import get_vulnerability_details
from brs_kb.reverse_map import find_contexts_for_payload


def demonstrate_splunk_integration():
    """Demonstrate Splunk integration capabilities"""
    print("🔍 Splunk Integration Demo")
    print("=" * 50)
    print()

    print("📋 Splunk Features:")
    features = [
        "• Real-time XSS vulnerability data ingestion",
        "• Custom dashboards for XSS context analysis",
        "• Alerting rules for critical vulnerabilities",
        "• Correlation with existing security events",
        "• Historical trend analysis",
        "• Professional security team interface"
    ]

    for feature in features:
        print(f"   {feature}")

    print()
    print("🚀 Usage Example:")
    print("   # Send vulnerability to Splunk")
    print("   connector = BRSKBSplunkConnector(api_key, splunk_url, index)")
    print("   connector.send_vulnerability_event(vulnerability_data)")
    print()

    # Simulate Splunk integration
    print("🔍 Example Vulnerability Data for Splunk:")
    vulnerability = get_vulnerability_details('websocket_xss')

    splunk_data = {
        "context": "websocket_xss",
        "severity": vulnerability["severity"],
        "cvss_score": vulnerability["cvss_score"],
        "description": vulnerability["description"][:100] + "...",
        "remediation": vulnerability["remediation"][:100] + "...",
        "cwe": vulnerability["cwe"],
        "owasp": vulnerability["owasp"],
        "tags": vulnerability["tags"]
    }

    print(json.dumps(splunk_data, indent=2))
    print()


def demonstrate_elasticsearch_integration():
    """Demonstrate Elasticsearch integration capabilities"""
    print("📊 Elasticsearch Integration Demo")
    print("=" * 50)
    print()

    print("📋 Elasticsearch Features:")
    features = [
        "• Real-time log ingestion via Logstash",
        "• Kibana dashboards for XSS analysis",
        "• Machine learning anomaly detection",
        "• Correlation with SIEM data",
        "• Alerting via Elasticsearch Watcher",
        "• Advanced search and analytics"
    ]

    for feature in features:
        print(f"   {feature}")

    print()
    print("🚀 Usage Example:")
    print("   # Send document to Elasticsearch")
    print("   connector = BRSKBElasticConnector(es_url, index_prefix)")
    print("   connector.send_vulnerability_document(vulnerability_data)")
    print()

    # Simulate Elasticsearch integration
    print("🔍 Example Document for Elasticsearch:")
    vulnerability = get_vulnerability_details('html_content')

    es_document = {
        "event_type": "xss_vulnerability_detected",
        "context": "html_content",
        "severity": vulnerability["severity"],
        "cvss_score": vulnerability["cvss_score"],
        "title": vulnerability["title"],
        "description": vulnerability["description"][:200] + "...",
        "remediation": vulnerability["remediation"][:200] + "...",
        "cwe": vulnerability["cwe"],
        "owasp": vulnerability["owasp"],
        "tags": vulnerability["tags"],
        "metadata": {
            "source_system": "brs_kb",
            "version": "3.0.0"
        }
    }

    print(json.dumps(es_document, indent=2))
    print()


def demonstrate_graylog_integration():
    """Demonstrate Graylog integration capabilities"""
    print("📋 Graylog Integration Demo")
    print("=" * 50)
    print()

    print("📋 Graylog Features:")
    features = [
        "• Real-time log ingestion via GELF",
        "• Custom dashboards and widgets",
        "• Alerting rules and notifications",
        "• Search and correlation capabilities",
        "• Stream processing for XSS events",
        "• Professional log management interface"
    ]

    for feature in features:
        print(f"   {feature}")

    print()
    print("🚀 Usage Example:")
    print("   # Send GELF log to Graylog")
    print("   connector = BRSKBGraylogConnector(graylog_url, gelf_port)")
    print("   connector.send_vulnerability_log(vulnerability_data)")
        print()
        
    # Simulate Graylog integration
    print("🔍 Example GELF Log for Graylog:")
    vulnerability = get_vulnerability_details('template_injection')

    gelf_log = {
        "short_message": f"XSS Vulnerability: {vulnerability['title']}",
        "full_message": vulnerability["description"][:300] + "...",
        "facility": "brs-kb-security",
        "level": 3,  # Error level
        "_event_type": "xss_vulnerability",
        "_source": "brs_kb",
        "_context": "template_injection",
        "_severity": vulnerability.get("severity", "unknown"),
        "_cvss_score": vulnerability.get("cvss_score", 0.0),
        "_cwe": vulnerability.get("cwe", []),
        "_owasp": vulnerability.get("owasp", [])
    }

    print(json.dumps(gelf_log, indent=2))
        print()
        

def demonstrate_enterprise_integration():
    """Demonstrate enterprise SIEM integration"""
    print("🏢 Enterprise SIEM Integration")
    print("=" * 50)
        print()
        
    print("📊 Multi-SIEM Architecture:")
    print("   ┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐")
    print("   │   BRS-KB API    │───▶│    Splunk       │    │  Elasticsearch   │")
    print("   │                 │    │   Enterprise    │    │     (ELK)       │")
    print("   │ Vulnerability   │    │                 │    │                 │")
    print("   │    Analysis     │───▶│   Dashboards    │───▶│   Analytics     │")
    print("   │                 │    │                 │    │                 │")
    print("   │   27 Contexts   │    │   Alerting      │    │   Machine       │")
    print("   │   200+ Payloads │    │                 │    │   Learning      │")
    print("   └─────────────────┘    └─────────────────┘    └─────────────────┘")
    print("           │                       │                       │")
    print("           └───────────────────────┼───────────────────────┘")
    print("                                   ▼")
    print("                          ┌─────────────────┐")
    print("                          │    Graylog      │")
    print("                          │   Open Source   │")
    print("                          │   Log Analysis  │")
    print("                          └─────────────────┘")
        print()
        
    print("🔧 Integration Benefits:")
    benefits = [
        "• Centralized XSS vulnerability monitoring",
        "• Real-time alerting for critical findings",
        "• Historical trend analysis and reporting",
        "• Correlation with existing security events",
        "• Compliance and audit trail support",
        "• Multi-platform security visibility"
    ]

    for benefit in benefits:
        print(f"   {benefit}")

            print()


def demonstrate_real_time_monitoring():
    """Demonstrate real-time monitoring capabilities"""
    print("⚡ Real-Time Monitoring Demo")
    print("=" * 50)
    print()

    print("📊 Live Vulnerability Detection:")
    print("   1. BRS-KB analyzes web requests")
    print("   2. XSS vulnerabilities detected")
    print("   3. Context automatically identified")
    print("   4. CVSS score calculated")
    print("   5. Remediation guidance provided")
    print("   6. Data sent to SIEM systems")
    print("   7. Alerts triggered for critical findings")
    print()
    
    # Simulate real-time analysis
    print("🔍 Real-Time Analysis Example:")
    test_payload = "<script>alert('Real-time XSS')</script>"
    analysis = find_contexts_for_payload(test_payload)

    print(f"   Payload: {test_payload}")
    print(f"   Context: {analysis['contexts'][0]}")
    print(f"   Severity: {analysis['severity']}")
    print(f"   CVSS: {analysis['cvss_score'] if 'cvss_score' in analysis else 'N/A'}")
    print(f"   Confidence: {analysis['confidence']}")
    print()
    
    print("📡 SIEM Integration:")
    print("   → Splunk: Vulnerability event indexed")
    print("   → Elasticsearch: Document stored with analytics")
    print("   → Graylog: GELF log processed")
    print("   → Alerts: Critical vulnerability notifications sent")
        print()
    

def main():
    """Main demonstration function"""
    print("🚀 BRS-KB SIEM Integration Showcase")
    print("=" * 70)
    print()

    demonstrate_splunk_integration()
    demonstrate_elasticsearch_integration()
    demonstrate_graylog_integration()
    demonstrate_enterprise_integration()
    demonstrate_real_time_monitoring()

    print("=" * 70)
    print("✨ BRS-KB SIEM Integration Complete!")
    print("   Enterprise-ready XSS intelligence with professional SIEM integration.")
    print("   Ready for production security monitoring and alerting.")
    print("=" * 70)


if __name__ == "__main__":
    main()
#!/usr/bin/env python3

"""
BRS-KB Elasticsearch Integration Connector
Project: BRS-KB (BRS XSS Knowledge Base)
Company: EasyProTech LLC (www.easyprotech)
Dev: Brabus
Date: Sat 25 Oct 2025 12:00:00 UTC
Status: Created
Telegram: https://t.me/easyprotech

Elasticsearch integration for BRS-KB XSS vulnerability data ingestion and analysis
"""

import json
import time
from datetime import datetime
from typing import Any, Dict, List, Optional

import requests


# Version from single source
try:
    from brs_kb.version import __version__ as BRS_KB_VERSION
except ImportError:
    BRS_KB_VERSION = "4.0.0"  # Fallback for standalone use


class BRSKBElasticConnector:
    """BRS-KB Elasticsearch integration for log ingestion and analysis"""

    def __init__(
        self,
        elasticsearch_url: str,
        index_prefix: str = "brs-kb-security",
        username: Optional[str] = None,
        password: Optional[str] = None,
    ):
        """
        Initialize Elasticsearch connector

        Args:
            elasticsearch_url: Elasticsearch URL (e.g., https://elasticsearch:9200)
            index_prefix: Index name prefix
            username: Elasticsearch username (optional)
            password: Elasticsearch password (optional)
        """
        self.es_url = elasticsearch_url.rstrip("/")
        self.index_prefix = index_prefix
        self.username = username
        self.password = password

        self.session = requests.Session()
        if username and password:
            self.session.auth = (username, password)

        self.session.headers.update({"Content-Type": "application/json"})

    def send_vulnerability_document(
        self, vulnerability_data: Dict[str, Any], index_suffix: str = "vulnerabilities"
    ) -> bool:
        """
        Send XSS vulnerability document to Elasticsearch

        Args:
            vulnerability_data: Vulnerability information from BRS-KB
            index_suffix: Index suffix (e.g., "vulnerabilities", "alerts")

        Returns:
            bool: Success status
        """
        try:
            index_name = f"{self.index_prefix}-{index_suffix}"
            document_id = f"xss_{int(time.time())}_{vulnerability_data.get('context', 'unknown')}"

            # Format document for Elasticsearch
            document = self._format_vulnerability_document(vulnerability_data)
            document["@timestamp"] = datetime.utcnow().isoformat()

            # Send to Elasticsearch
            response = self.session.post(
                f"{self.es_url}/{index_name}/_doc/{document_id}", json=document, timeout=30
            )

            if response.status_code in [200, 201]:
                print(f" Vulnerability document indexed: {document_id}")
                return True
            else:
                print(f" Failed to index vulnerability: {response.status_code} - {response.text}")
                return False

        except Exception as e:
            print(f" Error sending vulnerability to Elasticsearch: {e}")
            return False

    def send_payload_analysis(self, analysis_data: Dict[str, Any]) -> bool:
        """
        Send payload analysis results to Elasticsearch

        Args:
            analysis_data: Payload analysis from BRS-KB

        Returns:
            bool: Success status
        """
        try:
            index_name = f"{self.index_prefix}-payloads"
            document_id = f"analysis_{int(time.time())}"

            document = self._format_payload_analysis_document(analysis_data)
            document["@timestamp"] = datetime.utcnow().isoformat()

            response = self.session.post(
                f"{self.es_url}/{index_name}/_doc/{document_id}", json=document, timeout=30
            )

            if response.status_code in [200, 201]:
                print(f" Payload analysis indexed: {document_id}")
                return True
            else:
                print(f" Failed to index payload analysis: {response.status_code}")
                return False

        except Exception as e:
            print(f" Error sending payload analysis to Elasticsearch: {e}")
            return False

    def create_index_mapping(self, index_suffix: str = "vulnerabilities") -> bool:
        """
        Create Elasticsearch index with proper mapping for BRS-KB data

        Args:
            index_suffix: Index suffix

        Returns:
            bool: Success status
        """
        try:
            index_name = f"{self.index_prefix}-{index_suffix}"

            mapping = {
                "mappings": {
                    "properties": {
                        "@timestamp": {"type": "date"},
                        "event_type": {"type": "keyword"},
                        "context": {"type": "keyword"},
                        "severity": {"type": "keyword"},
                        "cvss_score": {"type": "float"},
                        "confidence": {"type": "float"},
                        "payload": {"type": "text", "analyzer": "standard"},
                        "description": {"type": "text"},
                        "remediation": {"type": "text"},
                        "cwe": {"type": "keyword"},
                        "owasp": {"type": "keyword"},
                        "tags": {"type": "keyword"},
                        "browser_support": {"type": "keyword"},
                        "waf_evasion": {"type": "boolean"},
                        "metadata": {
                            "type": "object",
                            "properties": {
                                "source_system": {"type": "keyword"},
                                "version": {"type": "keyword"},
                                "analysis_method": {"type": "keyword"},
                            },
                        },
                    }
                }
            }

            response = self.session.put(f"{self.es_url}/{index_name}", json=mapping, timeout=30)

            if response.status_code in [200, 201]:
                print(f" Index mapping created: {index_name}")
                return True
            else:
                print(f" Failed to create index mapping: {response.status_code}")
                return False

        except Exception as e:
            print(f" Error creating index mapping: {e}")
            return False

    def _format_vulnerability_document(self, vulnerability_data: Dict[str, Any]) -> Dict[str, Any]:
        """Format vulnerability data for Elasticsearch ingestion"""
        return {
            "event_type": "xss_vulnerability_detected",
            "context": vulnerability_data.get("context", "unknown"),
            "severity": vulnerability_data.get("severity", "unknown"),
            "cvss_score": vulnerability_data.get("cvss_score", 0.0),
            "confidence": vulnerability_data.get("confidence", 0.0),
            "payload": vulnerability_data.get("payload", ""),
            "description": vulnerability_data.get("description", ""),
            "remediation": vulnerability_data.get("remediation", ""),
            "cwe": vulnerability_data.get("cwe", []),
            "owasp": vulnerability_data.get("owasp", []),
            "tags": vulnerability_data.get("tags", []),
            "browser_support": vulnerability_data.get("browser_support", []),
            "waf_evasion": vulnerability_data.get("waf_evasion", False),
            "metadata": {
                "source_system": "brs_kb",
                "version": BRS_KB_VERSION,
                "analysis_method": vulnerability_data.get("analysis_method", "unknown"),
            },
        }

    def _format_payload_analysis_document(self, analysis_data: Dict[str, Any]) -> Dict[str, Any]:
        """Format payload analysis data for Elasticsearch ingestion"""
        return {
            "event_type": "payload_analysis",
            "payload": analysis_data.get("payload", ""),
            "contexts": analysis_data.get("contexts", []),
            "severity": analysis_data.get("severity", "unknown"),
            "confidence": analysis_data.get("confidence", 0.0),
            "analysis_method": analysis_data.get("analysis_method", "unknown"),
            "effectiveness_score": analysis_data.get("effectiveness_score", 0.0),
            "risk_level": analysis_data.get("risk_level", "unknown"),
            "recommendations": analysis_data.get("recommendations", []),
            "browser_parsing": analysis_data.get("browser_parsing", {}),
            "waf_detected": analysis_data.get("waf_detected", []),
            "metadata": {"source_system": "brs_kb", "version": BRS_KB_VERSION},
        }

    def test_connection(self) -> bool:
        """Test connection to Elasticsearch"""
        try:
            response = self.session.get(f"{self.es_url}/_cluster/health", timeout=10)
            return response.status_code == 200
        except Exception:
            return False

    def search_vulnerabilities(self, query: Dict[str, Any], size: int = 100) -> Dict[str, Any]:
        """
        Search vulnerabilities in Elasticsearch

        Args:
            query: Elasticsearch query DSL
            size: Number of results to return

        Returns:
            Dict: Search results
        """
        try:
            search_body = {
                "query": query,
                "size": size,
                "sort": [{"@timestamp": {"order": "desc"}}],
            }

            response = self.session.post(
                f"{self.es_url}/{self.index_prefix}-vulnerabilities/_search",
                json=search_body,
                timeout=30,
            )

            if response.status_code == 200:
                return response.json()
            else:
                print(f" Search failed: {response.status_code}")
                return {}

        except Exception as e:
            print(f" Error searching Elasticsearch: {e}")
            return {}

    def create_kibana_dashboard(self, dashboard_name: str = "BRS-KB XSS Dashboard") -> bool:
        """
        Create Kibana dashboard for BRS-KB data visualization

        Args:
            dashboard_name: Name for the dashboard

        Returns:
            bool: Success status
        """
        try:
            # Create visualizations first
            visualizations = self._create_visualizations()

            # Create dashboard
            dashboard = {
                "title": dashboard_name,
                "hits": 0,
                "description": "BRS-KB XSS vulnerability analysis dashboard",
                "panelsJSON": json.dumps(visualizations),
                "optionsJSON": json.dumps({"hidePanelTitles": False, "useMargins": True}),
                "uiStateJSON": json.dumps({}),
                "kibanaSavedObjectMeta": {
                    "searchSourceJSON": json.dumps(
                        {
                            "version": True,
                            "query": {"query": "*", "language": "lucene"},
                            "filter": [],
                        }
                    )
                },
            }

            response = self.session.post(
                f"{self.es_url}/.kibana/_doc/dashboard:{dashboard_name.lower().replace(' ', '-')}",
                json=dashboard,
                timeout=30,
            )

            if response.status_code in [200, 201]:
                print(f" Kibana dashboard created: {dashboard_name}")
                return True
            else:
                print(f" Failed to create dashboard: {response.status_code}")
                return False

        except Exception as e:
            print(f" Error creating dashboard: {e}")
            return False

    def _create_visualizations(self) -> List[Dict[str, Any]]:
        """Create dashboard visualizations"""
        return [
            {
                "id": "xss-context-distribution",
                "type": "pie",
                "title": "XSS Context Distribution",
                "visState": json.dumps(
                    {
                        "type": "pie",
                        "params": {
                            "type": "pie",
                            "addTooltip": True,
                            "addLegend": True,
                            "legendPosition": "right",
                        },
                        "aggs": [
                            {
                                "id": "1",
                                "type": "terms",
                                "schema": "segment",
                                "params": {"field": "context", "size": 10},
                            }
                        ],
                    }
                ),
            },
            {
                "id": "severity-timeline",
                "type": "histogram",
                "title": "Severity Timeline",
                "visState": json.dumps(
                    {
                        "type": "histogram",
                        "params": {
                            "type": "histogram",
                            "grid": {"categoryLines": False},
                            "categoryAxes": [{"id": "CategoryAxis-1"}],
                            "valueAxes": [{"id": "ValueAxis-1"}],
                        },
                        "aggs": [
                            {
                                "id": "1",
                                "type": "date_histogram",
                                "schema": "segment",
                                "params": {"field": "@timestamp", "interval": "auto"},
                            },
                            {
                                "id": "2",
                                "type": "terms",
                                "schema": "group",
                                "params": {"field": "severity"},
                            },
                        ],
                    }
                ),
            },
        ]

    def create_alerting_rule(self, rule_name: str = "BRS-KB Critical XSS Alert") -> bool:
        """
        Create Elasticsearch Watcher alert for critical XSS vulnerabilities

        Args:
            rule_name: Name for the alerting rule

        Returns:
            bool: Success status
        """
        try:
            rule = {
                "trigger": {"schedule": {"interval": "5m"}},
                "input": {
                    "search": {
                        "request": {
                            "indices": [f"{self.index_prefix}-vulnerabilities"],
                            "body": {
                                "query": {
                                    "bool": {
                                        "filter": [
                                            {"range": {"cvss_score": {"gte": 7.0}}},
                                            {"range": {"@timestamp": {"gte": "now-5m"}}},
                                        ]
                                    }
                                }
                            },
                        }
                    }
                },
                "condition": {"compare": {"ctx.payload.hits.total": {"gt": 0}}},
                "actions": {
                    "send_email": {
                        "email": {
                            "to": ["security-team@company.com"],
                            "subject": "Critical XSS Vulnerability Detected",
                            "body": "Critical XSS vulnerability with CVSS {{ctx.payload.hits.hits.0._source.cvss_score}} detected in {{ctx.payload.hits.hits.0._source.context}} context.",
                        }
                    }
                },
            }

            response = self.session.put(
                f"{self.es_url}/_watcher/watch/{rule_name.lower().replace(' ', '-')}",
                json=rule,
                timeout=30,
            )

            if response.status_code in [200, 201]:
                print(f" Alerting rule created: {rule_name}")
                return True
            else:
                print(f" Failed to create alerting rule: {response.status_code}")
                return False

        except Exception as e:
            print(f" Error creating alerting rule: {e}")
            return False


def create_sample_elastic_data() -> List[Dict[str, Any]]:
    """Create sample data for Elasticsearch testing"""
    return [
        {
            "context": "websocket_xss",
            "severity": "high",
            "cvss_score": 7.5,
            "confidence": 0.95,
            "payload": '{"type": "chat", "message": "<script>alert(1)</script>"}',
            "description": "WebSocket XSS vulnerability detected",
            "remediation": "Implement message sanitization and CSP",
            "cwe": ["CWE-79"],
            "owasp": ["A03:2021"],
            "tags": ["websocket", "realtime", "json"],
            "analysis_method": "pattern_matching",
            "browser_support": ["chrome", "firefox", "safari", "edge"],
            "waf_evasion": False,
        },
        {
            "context": "html_content",
            "severity": "critical",
            "cvss_score": 8.8,
            "confidence": 1.0,
            "payload": "<script>alert('XSS')</script>",
            "description": "Classic script tag injection",
            "remediation": "Use HTML entity encoding",
            "cwe": ["CWE-79"],
            "owasp": ["A03:2021"],
            "tags": ["script", "classic", "basic"],
            "analysis_method": "payload_database",
            "browser_support": ["chrome", "firefox", "safari", "edge"],
            "waf_evasion": False,
        },
        {
            "context": "template_injection",
            "severity": "critical",
            "cvss_score": 9.0,
            "confidence": 0.98,
            "payload": "{{constructor.constructor('alert(1)')()}}",
            "description": "Template injection with sandbox escape",
            "remediation": "Use template sandboxing and AOT compilation",
            "cwe": ["CWE-94"],
            "owasp": ["A03:2021"],
            "tags": ["template", "sandbox-escape", "code-execution"],
            "analysis_method": "pattern_matching",
            "browser_support": ["chrome", "firefox", "safari", "edge"],
            "waf_evasion": True,
        },
    ]


def main():
    """Main function for testing and demonstration"""
    print("BRS-KB Elasticsearch Integration Connector")
    print("=" * 50)
    print()

    # Configuration
    es_url = "https://your-elasticsearch:9200"
    index_prefix = "brs_kb_security"
    username = "elastic"  # Optional
    password = "your-password"  # Optional

    # Initialize connector
    connector = BRSKBElasticConnector(es_url, index_prefix, username, password)

    print(" Connector initialized")
    print(f" Elasticsearch URL: {es_url}")
    print(f" Index Prefix: {index_prefix}")
    print()

    # Test connection
    if connector.test_connection():
        print(" Elasticsearch connection successful")
    else:
        print(" Elasticsearch connection failed")
        print("Please verify your Elasticsearch configuration")
        return 1

    print()

    # Create index mapping
    print(" Creating index mappings...")
    if connector.create_index_mapping("vulnerabilities"):
        print(" Vulnerability index mapping created")
    if connector.create_index_mapping("payloads"):
        print(" Payload analysis index mapping created")
    print()

    # Send sample vulnerability data
    print("📤 Sending sample vulnerability documents...")

    sample_data = create_sample_elastic_data()
    sent_count = 0

    for vuln_data in sample_data:
        if connector.send_vulnerability_document(vuln_data):
            sent_count += 1

    print(f" Sent {sent_count}/{len(sample_data)} vulnerability documents")
    print()

    # Create Kibana dashboard
    print(" Creating Kibana dashboard...")
    if connector.create_kibana_dashboard("BRS-KB XSS Analysis"):
        print(" Kibana dashboard created")
    print()

    # Create alerting rule
    print("🚨 Creating alerting rule...")
    if connector.create_alerting_rule("BRS-KB Critical XSS Alert"):
        print(" Alerting rule created")
    print()

    # Example search query
    print("🔍 Example Elasticsearch Query:")
    print("-" * 40)

    search_query = {
        "bool": {
            "filter": [
                {"term": {"severity": "critical"}},
                {"range": {"@timestamp": {"gte": "now-1h"}}},
            ]
        }
    }

    results = connector.search_vulnerabilities(search_query, size=5)

    if results and "hits" in results:
        print(f"Found {results['hits']['total']['value']} critical vulnerabilities")
        for hit in results["hits"]["hits"][:3]:
            source = hit["_source"]
            print(f"   • {source['context']}: {source['severity']} (CVSS: {source['cvss_score']})")
    print()

    print(" BRS-KB Elasticsearch integration demonstration complete!")
    print("Ready for production SIEM integration.")

    return 0


if __name__ == "__main__":
    exit(main())

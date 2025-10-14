#!/usr/bin/env python3

"""
Project: BRS-KB (BRS XSS Knowledge Base)
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: 2025-10-14 22:53:00 MSK
Status: Created
Telegram: https://t.me/easyprotech

Example: SIEM/SOC Integration with BRS-KB
"""

import json
from datetime import datetime
from typing import Dict, Any, List
from brs_kb import get_vulnerability_details, list_contexts


class SIEMIntegration:
    """Example SIEM integration using BRS-KB for threat intelligence."""
    
    def __init__(self, siem_endpoint: str = "https://siem.example.com/api/events"):
        self.siem_endpoint = siem_endpoint
        self.events: List[Dict[str, Any]] = []
    
    def create_security_event(
        self, 
        vulnerability_context: str,
        source_ip: str,
        target_url: str,
        payload: str,
        detected_at: datetime = None
    ) -> Dict[str, Any]:
        """
        Create a SIEM security event enriched with BRS-KB data.
        
        Args:
            vulnerability_context: XSS context type (e.g., 'html_content')
            source_ip: Attacker IP address
            target_url: Target URL
            payload: Attack payload
            detected_at: Detection timestamp
        
        Returns:
            SIEM-formatted security event
        """
        if detected_at is None:
            detected_at = datetime.now()
        
        # Get vulnerability details from KB
        kb_details = get_vulnerability_details(vulnerability_context)
        
        # Create SIEM event
        event = {
            # Event metadata
            "event_id": f"XSS-{detected_at.strftime('%Y%m%d%H%M%S')}",
            "timestamp": detected_at.isoformat(),
            "event_type": "web_attack",
            "attack_category": "xss",
            
            # Threat data
            "source_ip": source_ip,
            "target_url": target_url,
            "payload": payload,
            "context": vulnerability_context,
            
            # KB enrichment
            "vulnerability_title": kb_details.get('title', 'Unknown XSS'),
            "severity": kb_details.get('severity', 'unknown'),
            "cvss_score": kb_details.get('cvss_score', 0.0),
            "cvss_vector": kb_details.get('cvss_vector', ''),
            "reliability": kb_details.get('reliability', 'tentative'),
            "cwe_ids": kb_details.get('cwe', []),
            "owasp_category": kb_details.get('owasp', []),
            "tags": kb_details.get('tags', []),
            
            # Threat intelligence
            "threat_level": self._calculate_threat_level(kb_details),
            "priority": self._calculate_priority(kb_details),
            "requires_immediate_action": self._requires_immediate_action(kb_details),
            
            # Additional context
            "description": kb_details.get('description', '')[:500],
            "recommended_action": self._extract_first_remediation(kb_details),
        }
        
        self.events.append(event)
        return event
    
    def _calculate_threat_level(self, kb_details: Dict[str, Any]) -> int:
        """Calculate numerical threat level (1-10) based on KB data."""
        severity = kb_details.get('severity', 'low')
        cvss = kb_details.get('cvss_score', 0.0)
        
        severity_map = {'low': 2, 'medium': 5, 'high': 8, 'critical': 10}
        base_level = severity_map.get(severity, 0)
        
        # Adjust based on CVSS
        if cvss >= 9.0:
            return 10
        elif cvss >= 7.0:
            return max(base_level, 8)
        elif cvss >= 4.0:
            return max(base_level, 5)
        
        return base_level
    
    def _calculate_priority(self, kb_details: Dict[str, Any]) -> str:
        """Calculate priority for SOC triage."""
        threat_level = self._calculate_threat_level(kb_details)
        
        if threat_level >= 9:
            return "P1 - Critical"
        elif threat_level >= 7:
            return "P2 - High"
        elif threat_level >= 4:
            return "P3 - Medium"
        else:
            return "P4 - Low"
    
    def _requires_immediate_action(self, kb_details: Dict[str, Any]) -> bool:
        """Determine if immediate action is required."""
        severity = kb_details.get('severity', 'low')
        reliability = kb_details.get('reliability', 'tentative')
        
        return (severity in ['critical', 'high']) and (reliability == 'certain')
    
    def _extract_first_remediation(self, kb_details: Dict[str, Any]) -> str:
        """Extract first actionable remediation step."""
        remediation = kb_details.get('remediation', '')
        
        # Extract first meaningful line
        for line in remediation.split('\n'):
            line = line.strip()
            if line and len(line) > 20 and not line.startswith('#'):
                return line[:200]
        
        return "Review KB for detailed remediation steps"
    
    def export_to_json(self, filename: str = "siem_events.json"):
        """Export events to JSON file for SIEM ingestion."""
        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(self.events, f, indent=2)
        print(f"Exported {len(self.events)} events to {filename}")
    
    def print_dashboard(self):
        """Print SOC dashboard summary."""
        if not self.events:
            print("No events to display")
            return
        
        print("=" * 80)
        print("SOC DASHBOARD - XSS THREAT INTELLIGENCE")
        print("=" * 80)
        print()
        
        # Summary statistics
        total = len(self.events)
        by_severity = {}
        by_context = {}
        immediate_action = 0
        
        for event in self.events:
            severity = event['severity']
            context = event['context']
            
            by_severity[severity] = by_severity.get(severity, 0) + 1
            by_context[context] = by_context.get(context, 0) + 1
            
            if event['requires_immediate_action']:
                immediate_action += 1
        
        print(f"Total Events: {total}")
        print(f"Require Immediate Action: {immediate_action}")
        print()
        
        print("Events by Severity:")
        for severity in ['critical', 'high', 'medium', 'low']:
            count = by_severity.get(severity, 0)
            print(f"  {severity.upper():8s}: {count:3d}")
        print()
        
        print("Top Attack Contexts:")
        sorted_contexts = sorted(by_context.items(), key=lambda x: x[1], reverse=True)
        for context, count in sorted_contexts[:5]:
            print(f"  {context:20s}: {count:3d}")
        print()
        
        print("Recent High-Priority Events:")
        print("-" * 80)
        high_priority = [e for e in self.events if e['threat_level'] >= 7]
        for event in high_priority[:3]:
            print(f"[{event['priority']}] {event['vulnerability_title']}")
            print(f"  Target: {event['target_url']}")
            print(f"  CVSS: {event['cvss_score']} | Context: {event['context']}")
            print()


def main():
    """Demonstrate SIEM integration."""
    
    print("BRS-KB SIEM Integration Example")
    print("=" * 80)
    print()
    
    # Create SIEM integration instance
    siem = SIEMIntegration()
    
    # Simulate detecting various XSS attacks
    attacks = [
        {
            'context': 'html_content',
            'ip': '192.168.1.100',
            'url': 'https://example.com/comment',
            'payload': '<script>steal_cookies()</script>'
        },
        {
            'context': 'dom_xss',
            'ip': '10.0.0.50',
            'url': 'https://example.com/app',
            'payload': 'location.hash payload'
        },
        {
            'context': 'template_injection',
            'ip': '172.16.0.25',
            'url': 'https://example.com/render',
            'payload': '{{constructor.constructor("alert(1)")()}}'
        },
        {
            'context': 'html_attribute',
            'ip': '192.168.1.101',
            'url': 'https://example.com/profile',
            'payload': '" onerror=alert(1) x="'
        },
        {
            'context': 'css_context',
            'ip': '10.0.0.51',
            'url': 'https://example.com/style',
            'payload': 'expression(alert(1))'
        },
    ]
    
    print("Processing security events...")
    print()
    
    for attack in attacks:
        event = siem.create_security_event(
            vulnerability_context=attack['context'],
            source_ip=attack['ip'],
            target_url=attack['url'],
            payload=attack['payload']
        )
        print(f"Created event: {event['event_id']} - {event['vulnerability_title']}")
        print(f"  Severity: {event['severity'].upper()} | Priority: {event['priority']}")
        print()
    
    # Display SOC dashboard
    print("\n")
    siem.print_dashboard()
    
    # Export to JSON
    print("=" * 80)
    siem.export_to_json()
    print()
    print("SIEM integration demonstration complete!")
    print("Events are enriched with comprehensive KB data for threat intelligence.")


if __name__ == "__main__":
    main()


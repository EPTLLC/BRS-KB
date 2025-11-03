#!/usr/bin/env python3

"""
Project: BRS-KB (BRS XSS Knowledge Base)
Company: EasyProTech LLC (www.easyprotech)
Dev: Brabus
Date: Sat 25 Oct 2025 12:00:00 UTC
Status: Created
Telegram: https://t.me/easyprotech

BRS-KB Command Line Interface
Comprehensive CLI for XSS vulnerability research and testing
"""

import argparse
import json
import sys
from typing import Dict, List, Any, Optional

# Import BRS-KB functions
from brs_kb import (
    get_kb_info,
    list_contexts,
    get_vulnerability_details,
    get_payloads_by_context,
    get_payloads_by_severity,
    search_payloads,
    analyze_payload_context,
    get_database_info,
    generate_payload_report,
    validate_payload_database,
)
from brs_kb.reverse_map import find_contexts_for_payload
from brs_kb.i18n import set_language, get_current_language, get_supported_languages, t


class BRSKBCLI:
    """BRS-KB Command Line Interface"""

    def __init__(self):
        self.parser = self._create_parser()

    def _create_parser(self) -> argparse.ArgumentParser:
        """Create argument parser"""
        parser = argparse.ArgumentParser(
            description="BRS-KB: Community XSS Knowledge Base CLI",
            formatter_class=argparse.RawDescriptionHelpFormatter,
            epilog="""
Examples:
  brs-kb list-contexts                    # Show all XSS contexts
  brs-kb get-context html_content         # Get HTML content XSS details
  brs-kb analyze-payload "<script>alert(1)</script>"  # Analyze payload
  brs-kb search-payloads script           # Search payloads
  brs-kb test-payload "<script>alert(1)</script>" html_content  # Test payload
  brs-kb generate-report                  # Generate comprehensive report
  brs-kb info                             # Show system information
  brs-kb language ru                      # Set language to Russian
  brs-kb language --list                  # List supported languages
            """,
        )

        subparsers = parser.add_subparsers(dest="command", help="Available commands")

        # list-contexts command
        subparsers.add_parser("list-contexts", help="List all available XSS contexts")

        # get-context command
        get_context_parser = subparsers.add_parser(
            "get-context", help="Get vulnerability details for a context"
        )
        get_context_parser.add_argument("context", help="Context name (e.g., html_content)")

        # analyze-payload command
        analyze_parser = subparsers.add_parser("analyze-payload", help="Analyze XSS payload")
        analyze_parser.add_argument("payload", help="Payload to analyze")

        # search-payloads command
        search_parser = subparsers.add_parser("search-payloads", help="Search payloads in database")
        search_parser.add_argument("query", help="Search query")
        search_parser.add_argument(
            "--limit", type=int, default=10, help="Maximum results (default: 10)"
        )

        # test-payload command
        test_parser = subparsers.add_parser("test-payload", help="Test payload effectiveness")
        test_parser.add_argument("payload", help="Payload to test")
        test_parser.add_argument("context", help="Context to test in")

        # generate-report command
        subparsers.add_parser("generate-report", help="Generate comprehensive system report")

        # info command
        subparsers.add_parser("info", help="Show system information")

        # validate command
        subparsers.add_parser("validate", help="Validate payload database integrity")

        # export command
        export_parser = subparsers.add_parser("export", help="Export data in various formats")
        export_parser.add_argument(
            "type", choices=["payloads", "contexts", "report"], help="Data type to export"
        )
        export_parser.add_argument(
            "--format", "-f", choices=["json", "text"], default="json", help="Export format"
        )
        export_parser.add_argument("--output", "-o", help="Output file (default: stdout)")

        # language command
        lang_parser = subparsers.add_parser("language", help="Set or show current language")
        lang_parser.add_argument("lang", nargs="?", help="Language code (en, ru, zh, es)")
        lang_parser.add_argument("--list", action="store_true", help="List supported languages")

        return parser

    def run(self, args: Optional[List[str]] = None) -> int:
        """Run CLI with provided arguments"""
        try:
            parsed_args = self.parser.parse_args(args)

            if not parsed_args.command:
                self.parser.print_help()
                return 1

            # Execute command
            if parsed_args.command == "list-contexts":
                return self._list_contexts()
            elif parsed_args.command == "get-context":
                return self._get_context(parsed_args.context)
            elif parsed_args.command == "analyze-payload":
                return self._analyze_payload(parsed_args.payload)
            elif parsed_args.command == "search-payloads":
                return self._search_payloads(parsed_args.query, parsed_args.limit)
            elif parsed_args.command == "test-payload":
                return self._test_payload(parsed_args.payload, parsed_args.context)
            elif parsed_args.command == "generate-report":
                return self._generate_report()
            elif parsed_args.command == "info":
                return self._show_info()
            elif parsed_args.command == "validate":
                return self._validate_database()
            elif parsed_args.command == "export":
                return self._export_data(parsed_args.type, parsed_args.format, parsed_args.output)
            elif parsed_args.command == "language":
                return self._handle_language(parsed_args.lang, parsed_args.list)

            return 0

        except KeyboardInterrupt:
            print("\nOperation cancelled by user")
            return 1
        except Exception as e:
            print(f"Error: {e}")
            return 1

    def _list_contexts(self) -> int:
        """List all available contexts with localization"""
        print(t("contexts.title"))
        print("=" * 50)

        contexts = list_contexts()
        kb_info = get_kb_info()

        print(f"{t('common.total')}: {len(contexts)} {t('contexts.payload_count')}")
        print()

        # Group contexts by type
        modern_contexts = [
            c
            for c in contexts
            if any(
                x in c
                for x in [
                    "websocket",
                    "service",
                    "webrtc",
                    "graphql",
                    "shadow",
                    "custom",
                    "http2",
                    "iframe",
                ]
            )
        ]
        legacy_contexts = [c for c in contexts if c not in modern_contexts and c != "default"]

        if modern_contexts:
            print("🔥 Modern Web Technologies:")
            for context in sorted(modern_contexts):
                details = get_vulnerability_details(context)
                severity = details.get("severity", "unknown")
                cvss = details.get("cvss_score", 0.0)
                print(f"   📍 {context} ({severity}, CVSS: {cvss})")
            print()

        if legacy_contexts:
            print("📜 Legacy/Classic Contexts:")
            for context in sorted(legacy_contexts):
                details = get_vulnerability_details(context)
                severity = details.get("severity", "unknown")
                cvss = details.get("cvss_score", 0.0)
                print(f"   📍 {context} ({severity}, CVSS: {cvss})")
            print()

        if "default" in contexts:
            print("Fallback Context:")
            print("   📍 default (generic XSS information)")
            print()

        return 0

    def _get_context(self, context: str) -> int:
        """Get detailed information about a context with localization"""
        try:
            details = get_vulnerability_details(context)

            print(f"XSS Context: {context.upper()}")
            print("=" * 50)
            print()

            print(f"Title: {details['title']}")
            print(f"Severity: {details['severity'].upper()}")
            print(f"CVSS Score: {details['cvss_score']}")
            print(f"Reliability: {details.get('reliability', 'unknown')}")
            print()

            if "cwe" in details and details["cwe"]:
                print(f"CWE: {', '.join(details['cwe'])}")
            if "owasp" in details and details["owasp"]:
                print(f"OWASP: {', '.join(details['owasp'])}")
            if "tags" in details and details["tags"]:
                print(f"🏷️  Tags: {', '.join(details['tags'])}")
            print()

            print("📝 Description:")
            print("-" * 30)
            # Truncate long descriptions
            description = details["description"].strip()
            if len(description) > 500:
                print(description[:500] + "...")
                print("   [truncated - use 'brs-kb get-context --full' for complete description]")
            else:
                print(description)
            print()

            # Show available payloads for this context
            payloads = get_payloads_by_context(context)
            if payloads:
                print(f"Available Payloads: {len(payloads)}")
                print("Top payloads:")
                for i, payload in enumerate(payloads[:3], 1):
                    print(f"   {i}. {payload['payload'][:60]}...")
                    print(f"      Tags: {', '.join(payload['tags'][:3])}")
                if len(payloads) > 3:
                    print(f"   ... and {len(payloads) - 3} more")
                print()

            return 0

        except Exception as e:
            print(f"Error: Context '{context}' not found")
            print(f"   Available contexts: {', '.join(list_contexts()[:5])}...")
            return 1

    def _analyze_payload(self, payload: str) -> int:
        """Analyze payload with reverse mapping"""
        print(f"Payload Analysis: {payload}")
        print("=" * 50)

        analysis = find_contexts_for_payload(payload)

        print(f"Analysis Method: {analysis['analysis_method']}")
        print(f"Confidence: {analysis['confidence']}")
        print(f"Severity: {analysis['severity'].upper()}")
        print()

        print("Effective Contexts:")
        if analysis["contexts"]:
            for context in analysis["contexts"]:
                details = get_vulnerability_details(context)
                print(f"   📍 {context} ({details['severity']}, CVSS: {details['cvss_score']})")
        else:
            print("   No contexts found")
        print()

        if "defenses" in analysis and analysis["defenses"]:
            print("🛡️ Required Defenses:")
            for defense in analysis["defenses"]:
                print(f"   🛡️ {defense}")
            print()

        if "waf_evasion" in analysis:
            print(f"🚨 WAF Evasion: {'Yes' if analysis['waf_evasion'] else 'No'}")

        if "browser_support" in analysis:
            print(f"🌐 Browser Support: {', '.join(analysis['browser_support'])}")

        if "tags" in analysis:
            print(f"🏷️  Tags: {', '.join(analysis['tags'])}")

        return 0

    def _search_payloads(self, query: str, limit: int) -> int:
        """Search payloads in database"""
        print(f"🔍 Searching payloads for: '{query}'")
        print("=" * 50)

        results = search_payloads(query)

        if not results:
            print("No payloads found")
            return 1

        print(f"Found {len(results)} results (showing top {min(limit, len(results))})")
        print()

        for i, result in enumerate(results[:limit], 1):
            payload_info = result
            print(f"{i}. {payload_info['payload'][:60]}...")
            print(f"   Contexts: {', '.join(payload_info['contexts'])}")
            print(f"   Severity: {payload_info['severity']} (CVSS: {payload_info['cvss_score']})")
            print(f"   Relevance: {payload_info['relevance_score']}")
            print(f"   WAF Evasion: {'Yes' if payload_info.get('waf_evasion') else 'No'}")
            print()

        if len(results) > limit:
            print(f"... and {len(results) - limit} more results")

        return 0

    def _test_payload(self, payload: str, context: str) -> int:
        """Test payload in specific context"""
        print(f"🧪 Testing Payload: {payload}")
        print(f"🎯 Context: {context}")
        print("=" * 50)

        try:
            test_result = analyze_payload_context(payload, context)

            print(f"Effectiveness Score: {test_result['effectiveness_score']}")
            print(f"Risk Level: {test_result['risk_level'].upper()}")
            print()

            print("🔍 Browser Parsing Results:")
            parsing = test_result["browser_parsing"]
            print(f"   Script Execution: {'✅' if parsing['script_execution'] else '❌'}")
            print(f"   HTML Injection: {'✅' if parsing['html_injection'] else '❌'}")
            print(f"   Event Execution: {'✅' if parsing['event_execution'] else '❌'}")
            print(f"   CSS Injection: {'✅' if parsing['css_injection'] else '❌'}")
            print()

            if test_result["waf_detected"]:
                print(f"🚨 WAF Detection: {', '.join(test_result['waf_detected'])}")
            else:
                print("🚨 WAF Detection: None")
            print()

            print("💡 Security Recommendations:")
            for rec in test_result["recommendations"]:
                print(f"   • {rec}")

            return 0

        except Exception as e:
            print(f"❌ Error testing payload: {e}")
            return 1

    def _generate_report(self) -> int:
        """Generate comprehensive system report"""
        print("Generating Comprehensive BRS-KB Report...")
        print("=" * 50)

        try:
            report = generate_payload_report()
            print(report)
            return 0

        except Exception as e:
            print(f"❌ Error generating report: {e}")
            return 1

    def _show_info(self) -> int:
        """Show system information"""
        print(f"{t('app.name')}")
        print("=" * 50)

        kb_info = get_kb_info()
        db_info = get_database_info()

        print(f"{t('app.version')}: {kb_info['version']}")
        print(f"Build: {kb_info['build']}")
        print(f"Revision: {kb_info['revision']}")
        print()

        print("Statistics:")
        print(f"   {t('contexts.title')}: {kb_info['total_contexts']}")
        print(f"   {t('payloads')}: {db_info['total_payloads']} payloads")
        print(f"   Detection Patterns: {len([p for p in dir() if 'pattern' in p.lower()])}")
        print(f"   WAF Bypass Payloads: {db_info['waf_bypass_count']}")
        print(f"   Supported Browsers: {len(db_info['browser_support'])}")
        print(f"   Unique Tags: {len(db_info['tags'])}")
        print()

        print("🎯 Available Commands:")
        print("   list-contexts    - Show all XSS contexts")
        print("   get-context      - Get context details")
        print("   analyze-payload  - Analyze XSS payload")
        print("   search-payloads  - Search payload database")
        print("   test-payload     - Test payload effectiveness")
        print("   generate-report  - Generate comprehensive report")
        print("   info             - Show this information")
        print("   validate         - Validate database integrity")
        print("   export           - Export data")
        print("   language         - Set or show current language")
        print()

        return 0

    def _validate_database(self) -> int:
        """Validate payload database integrity"""
        print("🔍 Validating Payload Database...")
        print("=" * 50)

        validation = validate_payload_database()

        print("✅ Validation Results:")
        print(f"   Total Payloads: {validation['total_payloads']}")
        print(f"   Contexts Covered: {len(validation['contexts_covered'])}")
        print(f"   Severities Found: {len(validation['severities_found'])}")
        print(f"   WAF Bypass Count: {validation['waf_bypass_count']}")
        print(f"   Unique Tags: {len(validation['tags_found'])}")
        print()

        if validation["errors"]:
            print("❌ Validation Errors:")
            for error in validation["errors"]:
                print(f"   • {error}")
            return 1
        else:
            print("✅ Database validation passed!")
            return 0

    def _export_data(self, data_type: str, format: str, output_file: str) -> int:
        """Export data in specified format"""
        print(f"📤 Exporting {data_type} as {format.upper()}...")
        print("=" * 50)

        try:
            data: Any
            if data_type == "payloads":
                from brs_kb import get_all_payloads

                data = get_all_payloads()
            elif data_type == "contexts":
                from brs_kb import get_all_contexts

                data = get_all_contexts()
            elif data_type == "report":
                data = generate_payload_report()
            else:
                print(f"❌ Unknown data type: {data_type}")
                return 1

            if format == "json":
                output = json.dumps(data, indent=2, ensure_ascii=False)
            else:
                output = str(data)

            if output_file:
                with open(output_file, "w", encoding="utf-8") as f:
                    f.write(output)
                print(f"✅ Exported to: {output_file}")
            else:
                print(output)

            return 0

        except Exception as e:
            print(f"❌ Export error: {e}")
            return 1

    def _handle_language(self, language: str, list_languages: bool) -> int:
        """Handle language command"""
        if list_languages:
            print("🌍 Supported Languages:")
            print("=" * 30)

            languages = get_supported_languages()
            for lang in languages:
                current = " (current)" if lang == get_current_language() else ""
                print(f"   {lang}{current}")

            print()
            print("Usage: brs-kb language <lang_code>")
            return 0

        if language:
            if set_language(language):
                print(f"✅ Language set to: {language}")
                print(f"🌍 Current language: {get_current_language()}")
            else:
                print(f"❌ Unsupported language: {language}")
                print("Supported languages: en, ru, zh, es")
                return 1
        else:
            print(f"🌍 Current language: {get_current_language()}")
            print("Usage: brs-kb language <lang_code>")
            print("       brs-kb language --list")

        return 0


def main():
    """Main CLI entry point"""
    cli = BRSKBCLI()
    return cli.run()


if __name__ == "__main__":
    sys.exit(main())

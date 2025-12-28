#!/usr/bin/env python3

"""
Project: BRS-KB (BRS XSS Knowledge Base)
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: 2025-10-25 12:00:00 UTC
Status: Created
Telegram: https://t.me/easyprotech

Tests for CLI module
"""

import io
from unittest.mock import MagicMock, patch

from brs_kb.cli import BRSKBCLI
from brs_kb.cli.cli import main
from brs_kb.version import __version__ as BRS_KB_VERSION


class TestBRSKBCLI:
    """Test BRSKBCLI class"""

    def test_cli_initialization(self):
        """Test CLI initialization"""
        cli = BRSKBCLI()
        assert cli is not None
        assert cli.parser is not None

    def test_parser_creation(self):
        """Test parser creation"""
        cli = BRSKBCLI()
        assert cli.parser is not None
        assert cli.commands is not None
        assert len(cli.commands) > 0

    def test_run_no_command(self):
        """Test running CLI without command"""
        cli = BRSKBCLI()
        with patch("sys.stdout", new=io.StringIO()) as fake_out:
            result = cli.run([])
            assert result == 1
            output = fake_out.getvalue()
            assert "BRS-KB" in output or "usage" in output.lower()

    def test_run_keyboard_interrupt(self):
        """Test handling KeyboardInterrupt"""
        cli = BRSKBCLI()
        with patch.object(cli.parser, "parse_args", side_effect=KeyboardInterrupt()):
            with patch("sys.stdout", new=io.StringIO()) as fake_out:
                result = cli.run()
                assert result == 1
                output = fake_out.getvalue()
                assert "cancelled" in output.lower() or "Operation cancelled" in output


class TestListContexts:
    """Test list-contexts command"""

    @patch("brs_kb.list_contexts")
    @patch("brs_kb.get_vulnerability_details")
    @patch("brs_kb.get_kb_info")
    def test_list_contexts_success(self, mock_info, mock_details, mock_list):
        """Test successful list contexts"""
        mock_list.return_value = ["html_content", "js_string", "dom_xss"]
        mock_info.return_value = {}
        mock_details.return_value = {"severity": "critical", "cvss_score": 8.8}
        cli = BRSKBCLI()

        with patch("sys.stdout", new=io.StringIO()) as fake_out:
            result = cli.run(["list-contexts"])
            assert result == 0
            output = fake_out.getvalue()
            assert "html_content" in output or len(output) > 0

    @patch("brs_kb.list_contexts")
    @patch("brs_kb.get_kb_info")
    def test_list_contexts_empty(self, mock_info, mock_list):
        """Test list contexts with empty result"""
        mock_list.return_value = []
        mock_info.return_value = {}
        cli = BRSKBCLI()

        result = cli.run(["list-contexts"])
        assert result == 0


class TestGetContext:
    """Test get-context command"""

    @patch("brs_kb.get_vulnerability_details")
    @patch("brs_kb.get_payloads_by_context")
    @patch("brs_kb.validation.validate_context_name")
    def test_get_context_success(self, mock_validate, mock_payloads, mock_get):
        """Test successful get context"""
        mock_validate.return_value = "html_content"
        mock_get.return_value = {
            "title": "HTML Content XSS",
            "description": "Test description",
            "severity": "critical",
            "cvss_score": 8.8,
            "reliability": "certain",
            "cwe": ["CWE-79"],
            "owasp": ["A03:2021"],
            "tags": ["xss"],
        }
        mock_payloads.return_value = []
        cli = BRSKBCLI()

        with patch("sys.stdout", new=io.StringIO()) as fake_out:
            result = cli.run(["get-context", "html_content"])
            assert result == 0
            output = fake_out.getvalue()
            assert len(output) > 0

    @patch("brs_kb.cli.commands.get_context.validate_context_name")
    def test_get_context_not_found(self, mock_validate):
        """Test get context with not found error"""
        from brs_kb.exceptions import ContextNotFoundError

        mock_validate.side_effect = ContextNotFoundError("invalid_context")
        cli = BRSKBCLI()

        result = cli.run(["get-context", "invalid_context"])
        assert result == 1


class TestAnalyzePayload:
    """Test analyze-payload command"""

    @patch("brs_kb.reverse_map.find_contexts_for_payload")
    @patch("brs_kb.get_vulnerability_details")
    @patch("brs_kb.validation.validate_payload")
    def test_analyze_payload_success(self, mock_validate, mock_get, mock_find):
        """Test successful payload analysis"""
        mock_validate.return_value = "<script>alert(1)</script>"
        mock_find.return_value = {
            "contexts": ["html_content"],
            "confidence": 0.95,
            "analysis_method": "pattern_matching",
            "severity": "critical",
        }
        mock_get.return_value = {"severity": "critical", "cvss_score": 8.8}
        cli = BRSKBCLI()

        with patch("sys.stdout", new=io.StringIO()) as fake_out:
            result = cli.run(["analyze-payload", "<script>alert(1)</script>"])
            assert result == 0
            output = fake_out.getvalue()
            assert len(output) > 0

    @patch("brs_kb.reverse_map.find_contexts_for_payload")
    @patch("brs_kb.validation.validate_payload")
    def test_analyze_payload_empty(self, mock_validate, mock_find):
        """Test analyze payload with empty result"""
        mock_validate.return_value = "unknown"
        mock_find.return_value = {
            "contexts": [],
            "confidence": 0.0,
            "analysis_method": "none",
            "severity": "low",
        }
        cli = BRSKBCLI()

        result = cli.run(["analyze-payload", "unknown"])
        assert result == 0


class TestSearchPayloads:
    """Test search-payloads command"""

    @patch("brs_kb.search_payloads")
    @patch("brs_kb.validation.validate_search_query")
    @patch("brs_kb.validation.validate_limit")
    def test_search_payloads_success(self, mock_limit, mock_query, mock_search):
        """Test successful payload search"""
        mock_query.return_value = "script"
        mock_limit.return_value = 10
        mock_search.return_value = [
            {
                "payload": "<script>alert(1)</script>",
                "contexts": ["html_content"],
                "severity": "critical",
                "cvss_score": 8.8,
                "relevance_score": 0.95,
                "waf_evasion": False,
            }
        ]
        cli = BRSKBCLI()

        with patch("sys.stdout", new=io.StringIO()) as fake_out:
            result = cli.run(["search-payloads", "script"])
            assert result == 0
            output = fake_out.getvalue()
            assert len(output) > 0

    @patch("brs_kb.cli.commands.search_payloads.search_payloads")
    @patch("brs_kb.cli.commands.search_payloads.validate_search_query")
    def test_search_payloads_with_limit(self, mock_query, mock_search):
        """Test search payloads with limit"""
        mock_query.return_value = "test"
        mock_search.return_value = [
            {
                "payload": "test_payload",
                "contexts": ["html_content"],
                "severity": "high",
                "cvss_score": 7.5,
                "relevance_score": 0.8,
                "waf_evasion": False,
            }
        ]
        cli = BRSKBCLI()

        result = cli.run(["search-payloads", "test", "--limit", "5"])
        assert result == 0

    @patch("brs_kb.validation.validate_search_query")
    def test_search_payloads_validation_error(self, mock_validate):
        """Test search payloads with validation error"""
        from brs_kb.exceptions import ValidationError

        mock_validate.side_effect = ValidationError("query", "", "Invalid query")
        cli = BRSKBCLI()

        result = cli.run(["search-payloads", ""])
        assert result == 1


class TestTestPayload:
    """Test test-payload command"""

    @patch("brs_kb.analyze_payload_context")
    @patch("brs_kb.validation.validate_context_name")
    @patch("brs_kb.validation.validate_payload")
    def test_test_payload_success(self, mock_validate_payload, mock_validate_context, mock_analyze):
        """Test successful payload testing"""
        mock_validate_payload.return_value = "<script>alert(1)</script>"
        mock_validate_context.return_value = "html_content"
        mock_analyze.return_value = {
            "effectiveness_score": 0.95,
            "risk_level": "high",
            "browser_parsing": {
                "script_execution": True,
                "html_injection": True,
                "event_execution": False,
                "css_injection": False,
            },
            "waf_detected": False,
            "recommendations": [],
        }
        cli = BRSKBCLI()

        with patch("sys.stdout", new=io.StringIO()) as fake_out:
            result = cli.run(["test-payload", "<script>alert(1)</script>", "html_content"])
            assert result == 0
            output = fake_out.getvalue()
            assert len(output) > 0

    @patch("brs_kb.cli.commands.test_payload.validate_context_name")
    def test_test_payload_context_not_found(self, mock_validate):
        """Test test payload with context not found"""
        from brs_kb.exceptions import ContextNotFoundError

        mock_validate.side_effect = ContextNotFoundError("invalid_context")
        cli = BRSKBCLI()

        result = cli.run(["test-payload", "<script>alert(1)</script>", "invalid_context"])
        assert result == 1


class TestGenerateReport:
    """Test generate-report command"""

    @patch("brs_kb.generate_payload_report")
    def test_generate_report_success(self, mock_generate):
        """Test successful report generation"""
        mock_generate.return_value = {
            "total_contexts": 27,
            "total_payloads": 200,
            "summary": "Test report",
        }
        cli = BRSKBCLI()

        with patch("sys.stdout", new=io.StringIO()) as fake_out:
            result = cli.run(["generate-report"])
            assert result == 0
            output = fake_out.getvalue()
            assert len(output) > 0


class TestShowInfo:
    """Test info command"""

    @patch("brs_kb.get_kb_info")
    @patch("brs_kb.get_database_info")
    def test_show_info_success(self, mock_db, mock_info):
        """Test successful info display"""
        mock_info.return_value = {
            "version": BRS_KB_VERSION,
            "total_contexts": 27,
            "build": "test",
            "revision": "test",
            "available_contexts": ["html_content"],
        }
        mock_db.return_value = {
            "total_payloads": 200,
            "contexts_covered": ["html_content"],
            "waf_bypass_count": 10,
            "browser_support": ["Chrome", "Firefox"],
            "tags": ["xss", "html"],
        }
        cli = BRSKBCLI()

        with patch("sys.stdout", new=io.StringIO()) as fake_out:
            result = cli.run(["info"])
            assert result == 0
            output = fake_out.getvalue()
            assert len(output) > 0


class TestValidateDatabase:
    """Test validate command"""

    @patch("brs_kb.cli.commands.validate.validate_payload_database")
    def test_validate_database_success(self, mock_validate):
        """Test successful database validation"""
        mock_validate.return_value = {
            "total_payloads": 200,
            "contexts_covered": ["html_content"],
            "severities_found": ["critical", "high"],
            "tags_found": ["xss", "html"],
            "waf_bypass_count": 10,
            "errors": [],
            "valid": True,
        }
        cli = BRSKBCLI()

        with patch("sys.stdout", new=io.StringIO()) as fake_out:
            result = cli.run(["validate"])
            assert result == 0
            output = fake_out.getvalue()
            assert len(output) > 0

    @patch("brs_kb.cli.commands.validate.validate_payload_database")
    def test_validate_database_with_errors(self, mock_validate):
        """Test database validation with errors"""
        mock_validate.return_value = {
            "total_payloads": 200,
            "contexts_covered": ["html_content"],
            "severities_found": ["critical"],
            "tags_found": ["xss"],
            "waf_bypass_count": 10,
            "errors": ["Error 1", "Error 2"],
            "valid": False,
        }
        cli = BRSKBCLI()

        result = cli.run(["validate"])
        assert result == 1  # Command returns 1 when there are errors


class TestExportData:
    """Test export command"""

    @patch("brs_kb.cli.commands.export.get_all_payloads")
    def test_export_payloads_json(self, mock_payloads):
        """Test exporting payloads as JSON"""
        mock_payloads.return_value = [
            {"payload": "<script>alert(1)</script>", "contexts": ["html_content"]}
        ]
        cli = BRSKBCLI()

        with patch("sys.stdout", new=io.StringIO()) as fake_out:
            result = cli.run(["export", "payloads", "--format", "json"])
            assert result == 0
            output = fake_out.getvalue()
            # Should contain JSON
            assert len(output) > 0

    @patch("brs_kb.get_all_contexts")
    @patch("brs_kb.get_vulnerability_details")
    def test_export_contexts_json(self, mock_get, mock_list):
        """Test exporting contexts as JSON"""
        mock_list.return_value = ["html_content"]
        mock_get.return_value = {"title": "Test", "description": "Test"}
        cli = BRSKBCLI()

        with patch("sys.stdout", new=io.StringIO()) as fake_out:
            result = cli.run(["export", "contexts", "--format", "json"])
            assert result == 0
            output = fake_out.getvalue()
            assert len(output) > 0

    @patch("brs_kb.generate_payload_report")
    def test_export_report_json(self, mock_report):
        """Test exporting report as JSON"""
        mock_report.return_value = {"summary": "Test report"}
        cli = BRSKBCLI()

        with patch("sys.stdout", new=io.StringIO()) as fake_out:
            result = cli.run(["export", "report", "--format", "json"])
            assert result == 0
            output = fake_out.getvalue()
            assert len(output) > 0

    @patch("brs_kb.get_all_contexts")
    @patch("brs_kb.get_vulnerability_details")
    def test_export_to_file(self, mock_get, mock_list):
        """Test exporting to file"""
        import os
        import tempfile

        mock_list.return_value = ["html_content"]
        mock_get.return_value = {"title": "Test", "description": "Test"}

        with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".json") as f:
            temp_file = f.name

        try:
            cli = BRSKBCLI()
            result = cli.run(["export", "contexts", "--format", "json", "--output", temp_file])
            assert result == 0

            # Check file was created
            if os.path.exists(temp_file):
                with open(temp_file) as f:
                    content = f.read()
                    assert len(content) > 0
        finally:
            if os.path.exists(temp_file):
                os.unlink(temp_file)


class TestMainFunction:
    """Test main function"""

    @patch("brs_kb.cli.cli.BRSKBCLI")
    def test_main_function(self, mock_cli_class):
        """Test main function"""
        mock_cli = MagicMock()
        mock_cli.run.return_value = 0
        mock_cli_class.return_value = mock_cli

        with patch("sys.exit") as mock_exit:
            main()
            mock_exit.assert_called_once_with(0)
        mock_cli.run.assert_called_once()

    @patch("sys.exit")
    def test_main_entry_point(self, mock_exit):
        """Test main entry point"""

        # Mock the CLI run method
        with patch("brs_kb.cli.cli.BRSKBCLI") as mock_cli_class:
            mock_cli = MagicMock()
            mock_cli.run.return_value = 0
            mock_cli_class.return_value = mock_cli

            main()
            mock_exit.assert_called_once_with(0)

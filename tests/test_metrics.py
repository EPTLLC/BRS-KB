#!/usr/bin/env python3

"""
Project: BRS-KB (BRS XSS Knowledge Base)
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: 2025-10-25 12:00:00 UTC
Status: Created
Telegram: https://t.me/easyprotech

Tests for metrics module
"""

import time

import pytest

from brs_kb.metrics import (
    MetricsCollector,
    get_metrics_collector,
    get_prometheus_metrics,
    record_context_access,
    record_error,
    record_payload_analysis,
    record_search_query,
    track_performance,
)


class TestMetricsCollector:
    """Test MetricsCollector class"""

    def test_collector_initialization(self):
        """Test collector initialization"""
        collector = MetricsCollector()
        assert collector._enabled is True
        assert len(collector._counters) == 0
        assert len(collector._gauges) == 0

    def test_increment_counter(self):
        """Test counter increment"""
        collector = MetricsCollector()
        collector.increment("test_counter")
        assert collector._counters["test_counter"] == 1.0

        collector.increment("test_counter", 2.0)
        assert collector._counters["test_counter"] == 3.0

    def test_increment_with_labels(self):
        """Test counter increment with labels"""
        collector = MetricsCollector()
        collector.increment("test_counter", labels={"label1": "value1"})
        key = "test_counter{label1=value1}"
        assert collector._counters[key] == 1.0

    def test_set_gauge(self):
        """Test gauge setting"""
        collector = MetricsCollector()
        collector.set_gauge("test_gauge", 42.0)
        assert collector._gauges["test_gauge"] == 42.0

        collector.set_gauge("test_gauge", 100.0)
        assert collector._gauges["test_gauge"] == 100.0

    def test_observe_histogram(self):
        """Test histogram observation"""
        collector = MetricsCollector()
        collector.observe_histogram("test_histogram", 1.0)
        collector.observe_histogram("test_histogram", 2.0)
        collector.observe_histogram("test_histogram", 3.0)

        assert len(collector._histograms["test_histogram"]) == 3
        assert collector._histograms["test_histogram"] == [1.0, 2.0, 3.0]

    def test_record_timing(self):
        """Test timing recording"""
        collector = MetricsCollector()
        collector.record_timing("test_timing", 0.5)
        collector.record_timing("test_timing", 1.0)

        assert len(collector._histograms["test_timing"]) == 2
        assert len(collector._timers["test_timing_total"]) == 2

    def test_enable_disable(self):
        """Test enable/disable functionality"""
        collector = MetricsCollector()
        collector.disable()
        collector.increment("test_counter")
        assert len(collector._counters) == 0

        collector.enable()
        collector.increment("test_counter")
        assert collector._counters["test_counter"] == 1.0

    def test_get_metrics_prometheus_format(self):
        """Test Prometheus format output"""
        collector = MetricsCollector()
        collector.increment("test_counter")
        collector.set_gauge("test_gauge", 42.0)
        collector.observe_histogram("test_histogram", 1.0)

        metrics = collector.get_metrics()
        assert "test_counter" in metrics
        assert "test_gauge" in metrics
        assert "test_histogram" in metrics
        assert "# TYPE" in metrics

    def test_reset(self):
        """Test metrics reset"""
        collector = MetricsCollector()
        collector.increment("test_counter")
        collector.set_gauge("test_gauge", 42.0)
        collector.observe_histogram("test_histogram", 1.0)

        collector.reset()
        assert len(collector._counters) == 0
        assert len(collector._gauges) == 0
        assert len(collector._histograms) == 0


class TestMetricFunctions:
    """Test metric recording functions"""

    def test_record_payload_analysis(self):
        """Test payload analysis recording"""
        collector = get_metrics_collector()
        collector.reset()

        record_payload_analysis("<script>alert(1)</script>", 0.1, 2, 0.95)

        assert "brs_kb_payload_analysis_duration" in str(collector.get_stats())
        assert collector._counters.get("brs_kb_payload_analyses_total", 0) > 0

    def test_record_search_query(self):
        """Test search query recording"""
        collector = get_metrics_collector()
        collector.reset()

        record_search_query("script", 0.05, 10)

        assert "brs_kb_search_duration" in str(collector.get_stats())
        assert collector._counters.get("brs_kb_searches_total", 0) > 0

    def test_record_context_access(self):
        """Test context access recording"""
        collector = get_metrics_collector()
        collector.reset()

        record_context_access("html_content", 0.01)

        assert "brs_kb_context_access_duration" in str(collector.get_stats())
        # Check for counter with label
        counter_key = "brs_kb_context_accesses_total{context=html_content}"
        assert collector._counters.get(counter_key, 0) > 0

    def test_record_error(self):
        """Test error recording"""
        collector = get_metrics_collector()
        collector.reset()

        record_error("validation_error", "html_content")

        assert (
            collector._counters.get(
                "brs_kb_errors_total{context=html_content,error_type=validation_error}", 0
            )
            > 0
        )


class TestPerformanceDecorator:
    """Test performance tracking decorator"""

    def test_track_performance_decorator(self):
        """Test performance tracking decorator"""
        collector = get_metrics_collector()
        collector.reset()

        @track_performance("test_function_duration")
        def test_function(value: int) -> int:
            """Test function for decorator"""
            time.sleep(0.01)  # Simulate work
            return value * 2

        result = test_function(5)
        assert result == 10

        # Check that metrics were recorded
        stats = collector.get_stats()
        assert "test_function_duration" in str(stats)

    def test_track_performance_with_error(self):
        """Test performance tracking with error"""
        collector = get_metrics_collector()
        collector.reset()

        @track_performance("test_function_with_error")
        def function_with_error():
            """Test function that raises error"""
            raise ValueError("Test error")

        with pytest.raises(ValueError):
            function_with_error()

        # Check that error was recorded
        assert collector._counters.get("test_function_with_error_errors", 0) > 0


class TestPrometheusMetrics:
    """Test Prometheus metrics output"""

    def test_get_prometheus_metrics(self):
        """Test getting Prometheus metrics"""
        collector = get_metrics_collector()
        collector.reset()

        # Record some metrics
        record_payload_analysis("<script>alert(1)</script>", 0.1, 1, 0.9)
        record_search_query("test", 0.05, 5)

        metrics = get_prometheus_metrics()
        assert isinstance(metrics, str)
        assert "brs_kb" in metrics
        assert "# TYPE" in metrics

    def test_metrics_format(self):
        """Test metrics format compliance"""
        collector = get_metrics_collector()
        collector.reset()

        collector.increment("test_counter")
        collector.set_gauge("test_gauge", 42.0)

        metrics = collector.get_metrics()
        lines = metrics.split("\n")

        # Check for TYPE declarations
        type_lines = [line for line in lines if line.startswith("# TYPE")]
        assert len(type_lines) > 0

        # Check for metric lines
        metric_lines = [line for line in lines if line and not line.startswith("#")]
        assert len(metric_lines) > 0


class TestSystemMetrics:
    """Test system metrics updates"""

    def test_update_system_metrics(self):
        """Test system metrics update"""
        from brs_kb.metrics import update_system_metrics

        collector = get_metrics_collector()
        collector.reset()

        update_system_metrics()

        # Check that system metrics were set
        stats = collector.get_stats()
        assert len(stats["gauges"]) > 0  # Should have system gauges

    def test_system_metrics_values(self):
        """Test system metrics have valid values"""
        from brs_kb.metrics import update_system_metrics

        collector = get_metrics_collector()
        collector.reset()

        update_system_metrics()

        # Check specific metrics
        stats = collector.get_stats()
        gauges = stats["gauges"]

        # Should have contexts_total
        context_keys = [k for k in gauges if "contexts_total" in k]
        assert len(context_keys) > 0

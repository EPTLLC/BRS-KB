#!/usr/bin/env python3

"""
Project: BRS-KB (BRS XSS Knowledge Base)
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: 2025-10-25 12:00:00 UTC
Status: Created
Telegram: https://t.me/easyprotech

Performance metrics module for BRS-KB
Provides Prometheus-compatible metrics for monitoring
"""

import time
from collections import defaultdict
from functools import wraps
from typing import Any, Callable, Dict, Optional

from brs_kb.logger import get_logger


logger = get_logger("brs_kb.metrics")


class MetricsCollector:
    """Collector for BRS-KB performance metrics"""

    def __init__(self):
        """Initialize metrics collector"""
        self._counters: Dict[str, float] = defaultdict(float)
        self._gauges: Dict[str, float] = {}
        self._histograms: Dict[str, list] = defaultdict(list)
        self._timers: Dict[str, list] = defaultdict(list)
        self._enabled = True

    def enable(self):
        """Enable metrics collection"""
        self._enabled = True

    def disable(self):
        """Disable metrics collection"""
        self._enabled = False

    def increment(
        self, metric_name: str, value: float = 1.0, labels: Optional[Dict[str, str]] = None
    ):
        """
        Increment a counter metric

        Args:
            metric_name: Name of the metric
            value: Value to increment by (default: 1.0)
            labels: Optional labels for the metric
        """
        if not self._enabled:
            return

        key = self._format_key(metric_name, labels)
        self._counters[key] += value

    def set_gauge(self, metric_name: str, value: float, labels: Optional[Dict[str, str]] = None):
        """
        Set a gauge metric value

        Args:
            metric_name: Name of the metric
            value: Value to set
            labels: Optional labels for the metric
        """
        if not self._enabled:
            return

        key = self._format_key(metric_name, labels)
        self._gauges[key] = value

    def observe_histogram(
        self, metric_name: str, value: float, labels: Optional[Dict[str, str]] = None
    ):
        """
        Observe a value in a histogram

        Args:
            metric_name: Name of the metric
            value: Value to observe
            labels: Optional labels for the metric
        """
        if not self._enabled:
            return

        key = self._format_key(metric_name, labels)
        self._histograms[key].append(value)
        # Keep only last 1000 values
        if len(self._histograms[key]) > 1000:
            self._histograms[key] = self._histograms[key][-1000:]

    def record_timing(
        self, metric_name: str, duration: float, labels: Optional[Dict[str, str]] = None
    ):
        """
        Record a timing metric

        Args:
            metric_name: Name of the metric
            duration: Duration in seconds
            labels: Optional labels for the metric
        """
        if not self._enabled:
            return

        self.observe_histogram(metric_name, duration, labels)
        key = self._format_key(metric_name + "_total", labels)
        self._timers[key].append(duration)

    def _format_key(self, metric_name: str, labels: Optional[Dict[str, str]]) -> str:
        """Format metric key with labels"""
        if not labels:
            return metric_name

        label_str = ",".join(f"{k}={v}" for k, v in sorted(labels.items()))
        return f"{metric_name}{{{label_str}}}"

    def get_metrics(self) -> str:
        """
        Get metrics in Prometheus format

        Returns:
            Metrics string in Prometheus exposition format
        """
        lines = []

        # Counters
        for key, value in sorted(self._counters.items()):
            lines.append(f"# TYPE {key.split('{')[0]} counter")
            lines.append(f"{key} {value}")

        # Gauges
        for key, value in sorted(self._gauges.items()):
            metric_name = key.split("{")[0]
            if metric_name not in [k.split("{")[0] for k in self._counters]:
                lines.append(f"# TYPE {metric_name} gauge")
            lines.append(f"{key} {value}")

        # Histograms (as summaries)
        for key, values in sorted(self._histograms.items()):
            if not values:
                continue

            metric_name = key.split("{")[0]
            lines.append(f"# TYPE {metric_name} summary")
            lines.append(f"{key}_count {len(values)}")
            lines.append(f"{key}_sum {sum(values)}")
            if values:
                sorted_values = sorted(values)
                lines.append(f"{key}_min {sorted_values[0]}")
                lines.append(f"{key}_max {sorted_values[-1]}")
                lines.append(f"{key}_avg {sum(values) / len(values)}")

        return "\n".join(lines) + "\n"

    def get_stats(self) -> Dict[str, Any]:
        """
        Get metrics statistics

        Returns:
            Dictionary with metrics statistics
        """
        stats = {
            "counters": dict(self._counters),
            "gauges": dict(self._gauges),
            "histograms": {
                k: {
                    "count": len(v),
                    "sum": sum(v),
                    "min": min(v) if v else 0,
                    "max": max(v) if v else 0,
                    "avg": sum(v) / len(v) if v else 0,
                }
                for k, v in self._histograms.items()
            },
        }
        return stats

    def reset(self):
        """Reset all metrics"""
        self._counters.clear()
        self._gauges.clear()
        self._histograms.clear()
        self._timers.clear()


# Global metrics collector instance
_metrics_collector = MetricsCollector()


def get_metrics_collector() -> MetricsCollector:
    """Get global metrics collector instance"""
    return _metrics_collector


def track_performance(metric_name: str, labels: Optional[Dict[str, str]] = None):
    """
    Decorator to track function performance

    Args:
        metric_name: Name of the metric
        labels: Optional labels for the metric

    Example:
        @track_performance("brs_kb_payload_analysis_duration")
        def analyze_payload(payload):
            ...
    """

    def decorator(func: Callable) -> Callable:
        @wraps(func)
        def wrapper(*args, **kwargs):
            collector = get_metrics_collector()
            start_time = time.time()

            try:
                result = func(*args, **kwargs)
                duration = time.time() - start_time
                collector.record_timing(metric_name, duration, labels)
                collector.increment(f"{metric_name}_total", labels=labels)
                return result
            except Exception:
                duration = time.time() - start_time
                collector.record_timing(metric_name, duration, labels)
                collector.increment(f"{metric_name}_errors", labels=labels)
                raise

        return wrapper

    return decorator


# Metric collection functions
def record_payload_analysis(payload: str, duration: float, contexts_found: int, confidence: float):
    """Record payload analysis metrics"""
    collector = get_metrics_collector()
    collector.record_timing("brs_kb_payload_analysis_duration", duration)
    collector.increment("brs_kb_payload_analyses_total")
    collector.set_gauge("brs_kb_payload_analysis_confidence", confidence)
    collector.set_gauge("brs_kb_payload_analysis_contexts_found", contexts_found)


def record_search_query(query: str, duration: float, results_count: int):
    """Record search query metrics"""
    collector = get_metrics_collector()
    collector.record_timing("brs_kb_search_duration", duration)
    collector.increment("brs_kb_searches_total")
    collector.set_gauge("brs_kb_search_results_count", results_count)


def record_context_access(context: str, duration: float):
    """Record context access metrics"""
    collector = get_metrics_collector()
    collector.record_timing("brs_kb_context_access_duration", duration, {"context": context})
    collector.increment("brs_kb_context_accesses_total", labels={"context": context})


def record_error(error_type: str, context: Optional[str] = None):
    """Record error metrics"""
    collector = get_metrics_collector()
    labels = {"error_type": error_type}
    if context:
        labels["context"] = context
    collector.increment("brs_kb_errors_total", labels=labels)


def record_cache_hit(metric_name: str):
    """Record cache hit"""
    collector = get_metrics_collector()
    collector.increment(f"{metric_name}_cache_hits")
    collector.increment(f"{metric_name}_cache_total")


def record_cache_miss(metric_name: str):
    """Record cache miss"""
    collector = get_metrics_collector()
    collector.increment(f"{metric_name}_cache_misses")
    collector.increment(f"{metric_name}_cache_total")


def update_system_metrics():
    """Update system-level metrics"""
    collector = get_metrics_collector()

    try:
        from brs_kb import get_database_info, list_contexts
        from brs_kb.payload_index import get_index

        # Context metrics
        contexts = list_contexts()
        collector.set_gauge("brs_kb_contexts_total", len(contexts))

        # Payload database metrics
        db_info = get_database_info()
        collector.set_gauge("brs_kb_payloads_total", db_info.get("total_payloads", 0))
        collector.set_gauge("brs_kb_contexts_covered", len(db_info.get("contexts_covered", [])))

        # Index metrics
        index = get_index()
        index_stats = index.get_index_stats()
        collector.set_gauge("brs_kb_index_payload_words", index_stats.get("payload_words", 0))
        collector.set_gauge("brs_kb_index_tags", index_stats.get("tags", 0))
        collector.set_gauge("brs_kb_index_waf_bypass_count", index_stats.get("waf_bypass_count", 0))

    except Exception as e:
        logger.warning("Failed to update system metrics: %s", e, extra={"error": str(e)})


def get_prometheus_metrics() -> str:
    """
    Get metrics in Prometheus format

    Returns:
        Metrics string in Prometheus exposition format
    """
    update_system_metrics()
    return get_metrics_collector().get_metrics()

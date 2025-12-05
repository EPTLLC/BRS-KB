# BRS-KB Metrics Documentation

**Project:** BRS-KB (BRS XSS Knowledge Base)  
**Version:** 2.0.0  
**Date:** 2025-10-25

## Overview

BRS-KB provides comprehensive performance metrics in Prometheus format for monitoring and observability.

## Metrics Endpoint

### HTTP Server

Start metrics server:
```python
from brs_kb.metrics_server import start_metrics_server

server = start_metrics_server(port=8000)
```

Or run standalone:
```bash
python -m brs_kb.metrics_server
```

### Endpoints

- `/metrics` - Prometheus metrics (text/plain)
- `/health` - Health check (application/json)

## Available Metrics

### Counter Metrics

- `brs_kb_payload_analyses_total` - Total number of payload analyses
- `brs_kb_searches_total` - Total number of search queries
- `brs_kb_context_accesses_total{context="..."}` - Total context accesses per context
- `brs_kb_errors_total{error_type="...", context="..."}` - Total errors by type

### Gauge Metrics

- `brs_kb_contexts_total` - Total number of contexts
- `brs_kb_payloads_total` - Total number of payloads
- `brs_kb_contexts_covered` - Number of contexts covered by payloads
- `brs_kb_payload_analysis_confidence` - Current analysis confidence
- `brs_kb_payload_analysis_contexts_found` - Number of contexts found
- `brs_kb_search_results_count` - Number of search results
- `brs_kb_index_payload_words` - Number of indexed payload words
- `brs_kb_index_tags` - Number of indexed tags
- `brs_kb_index_waf_bypass_count` - Number of WAF bypass payloads

### Histogram/Summary Metrics

- `brs_kb_payload_analysis_duration` - Payload analysis duration (seconds)
  - `_count` - Number of analyses
  - `_sum` - Total duration
  - `_min` - Minimum duration
  - `_max` - Maximum duration
  - `_avg` - Average duration

- `brs_kb_search_duration` - Search query duration (seconds)
  - `_count` - Number of searches
  - `_sum` - Total duration
  - `_min` - Minimum duration
  - `_max` - Maximum duration
  - `_avg` - Average duration

- `brs_kb_context_access_duration{context="..."}` - Context access duration (seconds)
  - `_count` - Number of accesses
  - `_sum` - Total duration
  - `_min` - Minimum duration
  - `_max` - Maximum duration
  - `_avg` - Average duration

## Usage Examples

### Recording Metrics

```python
from brs_kb.metrics import (
    record_payload_analysis,
    record_search_query,
    record_context_access,
    record_error
)

# Record payload analysis
record_payload_analysis(
    payload="<script>alert(1)</script>",
    duration=0.1,
    contexts_found=2,
    confidence=0.95
)

# Record search query
record_search_query(
    query="script",
    duration=0.05,
    results_count=10
)

# Record context access
record_context_access(
    context="html_content",
    duration=0.01
)

# Record error
record_error(
    error_type="validation_error",
    context="html_content"
)
```

### Using Performance Decorator

```python
from brs_kb.metrics import track_performance

@track_performance("my_function_duration")
def my_function():
    # Your code here
    pass
```

### Getting Metrics

```python
from brs_kb.metrics import get_prometheus_metrics

# Get metrics in Prometheus format
metrics = get_prometheus_metrics()
print(metrics)
```

## Prometheus Configuration

Example `prometheus.yml`:

```yaml
global:
  scrape_interval: 15s
  evaluation_interval: 15s

scrape_configs:
  - job_name: 'brs-kb'
    static_configs:
      - targets: ['localhost:8000']
    scrape_interval: 30s
    metrics_path: /metrics
```

## Alerting Rules

Example `alerts.yml`:

```yaml
groups:
  - name: brs-kb
    rules:
    - alert: BRSKBHighErrorRate
      expr: rate(brs_kb_errors_total[5m]) > 0.1
      for: 2m
      labels:
        severity: warning
      annotations:
        summary: "High error rate in BRS-KB"
        description: "BRS-KB is experiencing {{ $value }} errors per second"

    - alert: BRSKBSlowPayloadAnalysis
      expr: brs_kb_payload_analysis_duration_avg > 1.0
      for: 5m
      labels:
        severity: warning
      annotations:
        summary: "Slow payload analysis"
        description: "Average payload analysis time is {{ $value }}s"

    - alert: BRSKBLowPayloadDatabase
      expr: brs_kb_payloads_total < 100
      for: 5m
      labels:
        severity: warning
      annotations:
        summary: "Low payload database count"
        description: "BRS-KB payload database has {{ $value }} payloads"
```

## Grafana Dashboards

### Key Metrics to Monitor

1. **Performance Metrics**
   - Payload analysis duration (p50, p95, p99)
   - Search query duration
   - Context access duration

2. **Throughput Metrics**
   - Payload analyses per second
   - Search queries per second
   - Context accesses per second

3. **Error Metrics**
   - Error rate by type
   - Error rate by context

4. **System Metrics**
   - Total contexts
   - Total payloads
   - Index statistics

## Integration

### Docker

```dockerfile
# Expose metrics port
EXPOSE 8000

# Start metrics server
CMD ["python", "-m", "brs_kb.metrics_server"]
```

### Kubernetes

```yaml
apiVersion: v1
kind: Service
metadata:
  name: brs-kb-metrics
spec:
  ports:
  - port: 8000
    targetPort: 8000
    name: metrics
  selector:
    app: brs-kb
```

## References

- [ARCHITECTURE.md](./ARCHITECTURE.md) - System architecture
- [monitoring/prometheus.yml](../monitoring/prometheus.yml) - Prometheus configuration
- [monitoring/alerts.yml](../monitoring/alerts.yml) - Alerting rules



# Prometheus Metrics Contract

IronDome exposes metrics at `GET /metrics` in Prometheus exposition format. This document defines the stable metric names, labels, types, and semantics that monitoring systems can rely on.

## Endpoint

- **Path**: `/metrics`
- **Port**: Same as daemon port (default: 8443), or separate metrics port via `metrics.separatePort`
- **Auth**: Not required on separate metrics port; requires token on shared port
- **Format**: Prometheus text exposition format

## Configuration

```yaml
# values.yaml
monitoring:
  prometheus:
    enabled: true
    scrape: true
    port: 8443
    path: /metrics

metrics:
  separatePort: false
  port: 9100
```

## Service discovery

```yaml
# Prometheus scrape config
scrape_configs:
  - job_name: irondome
    kubernetes_sd_configs:
      - role: pod
        namespaces:
          names: [irondome]
    relabel_configs:
      - source_labels: [__meta_kubernetes_pod_label_app_kubernetes_io_name]
        action: keep
        regex: irondome
    metrics_path: /metrics
    scheme: https
    tls_config:
      insecure_skip_verify: true  # For self-signed certs
```

## Metrics

### Daemon health

| Metric | Type | Labels | Description |
|---|---|---|---|
| `irondome_up` | gauge | `version` | 1 if daemon is running, 0 otherwise |
| `irondome_health_status` | gauge | `component`, `status` | Health check result per component (1=healthy, 0=unhealthy) |
| `irondome_info` | gauge | `version`, `python_version`, `backend` | Build info (always 1) |

### Scan operations

| Metric | Type | Labels | Description |
|---|---|---|---|
| `irondome_scan_total` | counter | `verdict`, `backend` | Total number of scans completed |
| `irondome_scan_duration_seconds` | histogram | `backend`, `verdict` | Scan latency in seconds |
| `irondome_scan_errors_total` | counter | `error_type` | Total scan errors |
| `irondome_scan_findings` | histogram | `severity`, `rule` | Number of findings per scan |

### Admission controller

| Metric | Type | Labels | Description |
|---|---|---|---|
| `irondome_admission_requests_total` | counter | `allowed`, `operation`, `namespace` | Total admission requests processed |
| `irondome_admission_duration_seconds` | histogram | `operation` | Admission request processing time |
| `irondome_admission_image_scans_total` | counter | `image`, `allowed` | Total image scans performed |
| `irondome_admission_violations_total` | counter | `rule`, `namespace` | Total policy violations detected |

### Policy operations

| Metric | Type | Labels | Description |
|---|---|---|---|
| `irondome_policy_loads_total` | counter | `policy_name`, `version`, `verified` | Total policy loads |
| `irondome_policy_verification_failures_total` | counter | `policy_name`, `algorithm`, `key_id` | Total policy signature verification failures |
| `irondome_policy_changes_total` | counter | `action`, `policy_name` | Total policy create/update/rollback events |

### Rate limiting

| Metric | Type | Labels | Description |
|---|---|---|---|
| `irondome_rate_limit_requests_total` | counter | `result` (allowed/rejected) | Total rate limit decisions |
| `irondome_rate_limit_queue_depth` | gauge | `priority` | Current job queue depth by priority |
| `irondome_rate_limit_queue_wait_seconds` | histogram | `priority` | Time jobs spend waiting in queue |

### Webhook delivery

| Metric | Type | Labels | Description |
|---|---|---|---|
| `irondome_webhook_deliveries_total` | counter | `url`, `status` | Total webhook deliveries |
| `irondome_webhook_delivery_duration_seconds` | histogram | `url` | Webhook delivery latency |

### Audit

| Metric | Type | Labels | Description |
|---|---|---|---|
| `irondome_audit_events_total` | counter | `event_type` | Total audit events recorded |
| `irondome_audit_chain_integrity` | gauge | — | 1 if hash chain is intact, 0 otherwise |

### Storage

| Metric | Type | Labels | Description |
|---|---|---|---|
| `irondome_storage_bytes` | gauge | `type` (scan_results/audit_logs/baselines) | Storage usage in bytes |
| `irondome_storage_files` | gauge | `type` | Number of stored files |
| `irondome_retention_deletions_total` | counter | `type` | Total records deleted by retention policy |

### Tenant

| Metric | Type | Labels | Description |
|---|---|---|---|
| `irondome_tenant_scans_total` | counter | `tenant_id` | Scans per tenant |
| `irondome_tenant_violations_total` | counter | `tenant_id`, `rule` | Policy violations per tenant |

## Histogram buckets

Default buckets for latency histograms:

```python
# Scan latency
[0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0, 30.0]

# Queue wait time
[0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 5.0]

# Webhook delivery
[0.01, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0]
```

## Stability guarantees

- **Stable metric names**: Metric names starting with `irondome_` are stable and will not be renamed across minor versions
- **Label additions**: New labels may be added to existing metrics (non-breaking)
- **Label removal**: Labels will not be removed without a major version bump
- **Deprecation**: Deprecated metrics will emit a log warning for one minor version before removal

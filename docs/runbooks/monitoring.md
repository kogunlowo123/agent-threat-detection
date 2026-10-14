# Runbook: monitoring

Dashboards: `configs/grafana/agent-threat-detection.json`.
Alert rules: `configs/prometheus/alerts.yaml`.

## Key signals

| Signal | Healthy | Source |
|---|---|---|
| Ingestion success | ≥ 99.9% non-5xx | `atd:request_errors:ratio_5m` |
| Batch latency p99 | < 1 s | `atd_ingest_batch_duration_seconds` |
| Telemetry flow | Non-zero for every collector | `atd_events_ingested_total{source}` |
| Duplicates | Low single-digit percent | `atd_events_duplicate_total` (collector retries) |
| Rejected records | Near zero | `atd_events_rejected_total` |
| Open alerts | Trending with analyst capacity | `atd_open_alerts{severity}` |
| SIEM backlog | < 100 | `atd_siem_outbox_backlog` |
| Inbound authorization | Mostly `allow` | `atd_inbound_authorization_total{channel,outcome}` |

## Ingest latency

`ThreatDetectionIngestLatencyHigh`.

1. Check database latency (RDS Performance Insights / Azure Query Store /
   Cloud SQL Insights). Profile writes are one row per agent per batch.
2. Check CPU throttling on the pods; scale `autoscaling.maxReplicas` if the
   HPA is pinned at maximum.
3. Large conflicts (two replicas processing the same agent) show as retries
   in logs (`profile ... changed concurrently`). Partition collector output
   by `agent_id`.

## Telemetry gap

`ThreatDetectionTelemetryStopped`: detection is blind.

1. `kubectl -n agent-security logs statefulset/atd-agent-threat-detection | grep telemetry`
2. Check collector health and exporter errors. A wave of 401/403 responses
   means collector credentials expired or lost `telemetry:write` in the fabric.
3. Check `atd_inbound_authorization_total{outcome="temporarily_unavailable"}`:
   the fabric is unreachable and ingestion fails closed.

## SIEM backlog

`SiemDeliveryBacklog` / `SiemDeliveryFailing`.

1. Logs show `siem_delivery_failed` with the exception type.
2. Verify the collector URL and token (`THREAT_SIEM_URL`, secret
   `agent-threat-detection-siem-token`). A rotated token is picked up on the
   next delivery; no restart is needed.
3. Findings stay in `siem_outbox` until delivered; back-off caps at 15
   minutes, so delivery resumes within 15 minutes of the SIEM recovering.

## Detection quality

Track the share of alerts resolved as false positives per detector (audit
events `alert.resolve` with `resolution=false_positive`). A detector above
20% for two weeks needs a threshold review; record changes in
`docs/architecture/detection-evaluation.md` with re-measured rates.

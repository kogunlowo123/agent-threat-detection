# Runbook: disaster recovery

## Objectives

| Item | RPO | RTO |
|---|---|---|
| Alerts, containment records, profiles (PostgreSQL) | 5 minutes (point-in-time recovery) | 1 hour |
| Audit chains (WORM object storage) | Shipping interval of the log shipper | Not on the serving path |
| Pending SIEM findings | Same as PostgreSQL (outbox) | Delivered after restore |

## Region or database loss

1. Restore PostgreSQL to the latest point in time in the recovery region
   (RDS `restore-db-instance-to-point-in-time`, Azure Flexible Server
   geo-restore, Cloud SQL PITR).
2. Update the database URL secret; External Secrets syncs it within an hour,
   or force: `kubectl -n agent-security annotate externalsecret agent-threat-detection-database force-sync=$(date +%s) --overwrite`.
3. Install the chart in the recovery cluster (startup runbook steps 3–5).
4. Undelivered outbox rows are sent automatically; the SIEM deduplicates by
   `metadata.uid`.
5. Profiles restored to the recovery point miss up to five minutes of
   learning. Telemetry replayed by collectors after restore is processed
   normally; event ids already recorded are skipped.

## Profiles lost entirely

Detection keeps working without baselines: rules, credential scanning,
delegation cycles, denial bursts and injected-content detection are
baseline-independent. Statistical detectors re-arm once each agent reaches
maturity again (default 500 learned events and 72 hours). Expect fewer
behavioural alerts, not more, during that period.

## Audit chain verification after restore

Audit chains are per replica (`<pod>.jsonl`). Verify with agentic-core:

```python
from agentic_core.audit import AuditEvent, verify_chain
events = [AuditEvent.model_validate_json(line) for line in open("atd-agent-threat-detection-0.jsonl")]
verify_chain(events, {"audit-2026-10": public_key})
```

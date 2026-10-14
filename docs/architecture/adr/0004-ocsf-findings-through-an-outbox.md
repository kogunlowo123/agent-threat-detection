# ADR-0004: OCSF Detection Findings delivered through a transactional outbox

- Status: Accepted
- Date: 2026-10-14

## Context

Findings must reach the SIEM in a schema it understands without coupling
ingestion latency or availability to the SIEM. Delivering synchronously
during ingestion would make a SIEM outage either block telemetry or lose
findings.

## Decision

- Findings use OCSF 1.3 Detection Finding (class 2004, category Findings)
  with Create / Update / Close activities, severity and status ids, the
  analytic (rule or behavioural detector), ATT&CK and ATLAS attacks, the agent
  as a resource, and evidence event ids. OCSF is read natively by Amazon
  Security Lake, Splunk, Microsoft Sentinel and most security data lakes.
- Each alert change writes its finding to `siem_outbox` in the same database
  transaction as the alert.
- `SiemDispatcher` delivers due rows in batches of 100 to an HTTP collector
  (an OCSF JSON array with a bearer token, or Splunk HEC envelopes) or to a
  JSON Lines file for a log shipper, with exponential back-off capped at 15
  minutes. Delivered rows are purged after 7 days.

## Consequences

- Delivery is at least once: a crash between sending and recording delivery
  can resend a batch. `metadata.uid` (`alert_id:version`) lets the SIEM
  deduplicate.
- SIEM outages show up as `atd_siem_outbox_backlog` and delivery-failure
  alerts rather than lost findings.

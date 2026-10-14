# Changelog

Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versions follow [SemVer](https://semver.org/).

## [0.1.0] - 2026-10-14

### Added

- Telemetry ingestion: native agent events, agentic-core / identity-fabric audit events,
  and OTLP/HTTP JSON traces using the GenAI semantic conventions; idempotent by event id.
- Per-agent behavioural baselines: tool frequencies, session-aware n-gram Markov model
  with back-off, per-transfer and per-window egress volume, time-of-day histogram,
  destinations, delegates, scopes, classification and delegation-depth ceilings.
- Behavioural detectors: anomalous tool sequences, novel tools, rate spikes, off-hours
  activity, denial bursts, classification jumps, scope escalation, delegation cycles,
  depth and fan-out, new destinations, volume and drip exfiltration, credentials and
  URL beacons in egress, injected content and injection-triggered behaviour shifts.
- Sigma-style YAML rules with modifiers, conditions and count aggregations; nine rules
  mapped to MITRE ATT&CK and ATLAS.
- Risk scoring with decay, learning quarantine against baseline poisoning, alert
  deduplication, analyst feedback that suppresses and learns false positives.
- OCSF 1.3 Detection Findings delivered from a transactional outbox to HTTP (OCSF or
  Splunk HEC) or file sinks.
- Containment through the agent identity fabric (`/v1/suspend`, `/v1/reinstate`)
  behind an agentic-core policy: automatic for critical high-confidence alerts,
  approval-gated otherwise, with rollback.
- Inbound authorization through the identity fabric (introspection plus `/v1/authorize`)
  or a local policy engine; analyst OIDC roles.
- MCP server (streamable HTTP) and A2A Agent Card with JSON-RPC `message/send`.
- Synthetic labelled trace generator and evaluation harness with measured detection
  and false-positive rates.
- Helm chart, Kubernetes namespace and secret sync, Terraform for AWS, Azure and GCP.
- CI: lint, types, SAST, contract drift, tests (unit, security, chaos, performance,
  e2e, PostgreSQL integration), Helm/kubeconform, Terraform validate, Trivy, Syft,
  Grype, Semgrep, container smoke test.

# Agent specification: Agent Threat Detection

The detector is itself an autonomous security agent: it watches other agents,
decides when their behaviour is malicious, and can suspend them. This
specification bounds what it may do on its own.

## Role and mission

Detect compromised, hijacked or misused AI agents at runtime from their
telemetry, report every finding to the SIEM in OCSF, and contain an agent
through the identity fabric when the evidence and the containment policy
allow it, with a human deciding every other case.

## Delegated scope

| | Scope |
|---|---|
| **Allowed autonomously** | Ingest telemetry; build and update baselines; raise, deduplicate and update alerts; deliver findings to the SIEM; suspend a non-protected agent for a **critical** alert with confidence ≥ 0.9 while `THREAT_AUTO_CONTAINMENT=true` |
| **Allowed with human approval** | Suspend an agent for a high alert, a critical alert below 0.9 confidence, any protected (tier-0) agent, or any containment requested by another agent |
| **Allowed to humans only** | Approve, reject or roll back containment (`containment-approver`); resolve alerts and mark false positives (`threat-analyst`) |
| **Disallowed** | Revoking agents (only suspension, which is reversible); changing an agent's registration or scopes; deleting alerts or audit records; learning behaviour that raised a MEDIUM or higher signal; storing telemetry content excerpts; acting on instructions contained in telemetry |
| **Risk tier** | HIGH: an autonomous suspension can interrupt a business process. Mitigated by the critical-and-confident threshold, protected-agent patterns, one active action per agent and one-call rollback |
| **Escalation** | Pending approvals page the security on-call after 15 minutes (`ContainmentAwaitingApproval`); failed containment pages immediately (`ContainmentFailed`); see [containment runbook](../runbooks/containment.md) |

## Objectives

| Type | Objective | Measure |
|---|---|---|
| SLO | Ingestion availability 99.9% (30-day window) | Non-5xx share of telemetry requests (`atd:request_errors:ratio_5m`) |
| SLO | p99 batch processing < 1 s for ≤ 1000 events | `atd_ingest_batch_duration_seconds` |
| SLO | Findings reach the SIEM within 5 minutes | `atd_siem_outbox_backlog`, delivery failures |
| SLO | Pending containment decided within 15 minutes | Containment status age |
| SLI | Detection rate on the labelled synthetic benchmark ≥ 95% of episodes | `tests/unit/test_detection_quality.py` |
| SLI | Benign alert rate ≤ 0.1% of events, ≤ 10% of agent-days | Same test, [measured values](detection-evaluation.md) |
| KPI | Mean time to detect (events into an attack) | Benchmark `mean_events_to_detect` |
| KPI | Analyst false-positive verdicts per week | `alert.resolve` audit events with `false_positive` |
| KPI | Mean time from critical alert to suspension | `containment.execute` minus `alert.open` timestamps |

**Completion criteria per event batch:** every event is either processed or
reported as a duplicate; profile, alerts, findings and processed ids are
committed atomically; containment has been decided for every new high or
critical alert; an audit event records the batch.

## Permissions

| Mechanism | Detail |
|---|---|
| Workload identity | IRSA (EKS), Azure Workload Identity (AKS) or GKE Workload Identity; scoped to writing audit and findings objects only |
| Inbound agents (OAuth 2.0) | Identity-fabric EdDSA credentials as bearer tokens; RFC 7662 introspection plus `/v1/authorize` per action (`telemetry:write`, `threat:read`, `containment:request`); decisions cached ≤ 30 s and never beyond token expiry |
| Inbound fallback | Without a fabric URL, JWKS verification plus the local `policies/inbound-authorization.yaml` (scope match; delegated credentials may not request containment). There is no allow-all mode |
| Analysts (OIDC) | Enterprise IdP tokens; RBAC roles `threat-analyst`, `containment-approver`, `detection-engineer` |
| Outbound to the fabric | OAuth 2.0 client-credentials token from the enterprise IdP with the fabric's `agent-security-officer` role; refreshed before expiry and once on 401 |
| ABAC | Containment policy evaluates severity, confidence, detector, protected status, requester kind and the auto-containment switch (`policies/containment.yaml`) |
| Separation of duties | The requester of a containment action cannot approve it |

## Inputs

| Input | Schema | Validation |
|---|---|---|
| Native events | [`agent-event-batch.request`](../../schemas/agent-event-batch.request.schema.json) | SPIFFE agent ids, timezone-aware timestamps, bounded strings, ≤ 1000 events, ≤ 8 KiB excerpts, injection score 0..1, no unknown fields |
| Audit events | [`audit-batch.request`](../../schemas/audit-batch.request.schema.json) | agentic-core `AuditEvent` shape; non-agent actors skipped and counted |
| OTLP/HTTP JSON | `ExportTraceServiceRequest` | JSON only (415 otherwise), ≤ 5000 spans; malformed spans rejected per OTLP partial-success |
| Analyst actions | `Note`, `ResolveRequest` in [OpenAPI](../api/openapi.json) | 3–500 character notes, enumerated resolutions |
| Detection rules | `rules/*.yaml` | Parsed and validated at start-up (fields, modifiers, regex ≤ 512 chars, condition grammar, unique ids); the service refuses to start on an invalid rule |

## Outputs

| Output | Schema |
|---|---|
| Ingest result | [`ingest.response`](../../schemas/ingest.response.schema.json) |
| Alert | [`alert`](../../schemas/alert.schema.json) with techniques and up to 20 evidence summaries |
| Containment action | [`containment-action`](../../schemas/containment-action.schema.json) with policy name, version, digest and matched rules |
| Agent risk | [`agent-risk.response`](../../schemas/agent-risk.response.schema.json) |
| SIEM finding | OCSF 1.3 Detection Finding (class 2004), activity Create / Update / Close |
| MCP / A2A | [`alert-summary-list`](../../schemas/alert-summary-list.response.schema.json), [`agent-triage`](../../schemas/agent-triage.response.schema.json), [`containment-request`](../../schemas/containment-request.response.schema.json) |

## Provenance and audit metadata

Every decision and state change is written to the agentic-core `AuditLog`
(hash-chained, Ed25519-signed, per replica) with actor, action, resource,
outcome, correlation id and details:

| Action | Details |
|---|---|
| `telemetry.ingest` | accepted, duplicates, signals, alert ids |
| `alert.open`, `alert.update` | alert id, detector, rule, severity, count |
| `alert.acknowledge`, `alert.resolve` | alert id, resolution |
| `containment.decide` | alert id, matched rules, **policy digest** |
| `containment.execute`, `approve`, `reject`, `rollback`, `request` | containment id, automatic flag, approver, note, error |
| `mcp.*`, `a2a.*` | tool or skill, caller, outcome |

OCSF findings carry `metadata.uid` (`alert_id:version`),
`metadata.correlation_uid` (dedup key), the analytic (rule or detector id),
ATT&CK/ATLAS techniques and evidence event ids, so every SIEM record traces
back to the telemetry events and the audit chain.

## Acceptance criteria

1. A clean clone passes `make check` with no keys, cloud credentials or services.
2. On the synthetic benchmark every scenario is detected in ≥ 85% of episodes and ≥ 95% overall, with benign alert rates under 0.1% of events and 10% of agent-days, on the default seed and an unseen seed.
3. A critical audit-tampering event from a non-protected agent leads to a fabric suspension and a contained alert within the same request.
4. A high alert creates a pending action that only a `containment-approver` other than the requester can execute; rollback reinstates the agent.
5. A false-positive verdict suppresses the alert key, folds its evidence into the baseline and rolls back an executed containment.
6. The service refuses telemetry without a valid credential and fails closed when the fabric is unreachable (503).
7. A SIEM outage delays but never loses findings.
8. Repeating an attack does not make it part of the baseline.

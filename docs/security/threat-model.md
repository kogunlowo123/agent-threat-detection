# Threat model

Scope: the detector service, its inbound interfaces (REST telemetry and
analyst API, OTLP intake, MCP, A2A), its stores, and its outbound calls to
the identity fabric, the IdP and the SIEM. The agents it watches are the
subject of detection, covered in the second half of this document.

## Assets

| Asset | Why it matters |
|---|---|
| Containment authority (fabric `agent-security-officer` client) | Can suspend any agent; misuse is a denial-of-service weapon |
| Baselines | Poisoned baselines blind detection |
| Alerts, containment records, audit chains | Evidence for incident response and regulators |
| Detection rules and policies | Weakening them silently disables detection |
| Telemetry content excerpts | May contain sensitive data and secrets |

## Trust boundaries

1. Agents and collectors → detector (agent credentials, fabric-authorized per action).
2. Analysts → detector (enterprise OIDC, RBAC).
3. Detector → identity fabric (client-credentials admin token; introspection).
4. Detector → SIEM (bearer / HEC token over TLS).
5. Detector → PostgreSQL and object storage (workload identity, TLS).

## STRIDE

| ID | Threat | Mitigation | Test |
|---|---|---|---|
| S1 | Forged or replayed agent credential submits telemetry to frame or hide an agent | Fabric introspection and `/v1/authorize` per action; local mode verifies signature, issuer, audience, expiry, `kid`; `alg: none` rejected | `tests/security::test_forged_and_malformed_agent_credentials_are_rejected` |
| S2 | Impersonated analyst approves a containment | OIDC signature, issuer and audience checks; role required; requester cannot approve own request | `test_agents_cannot_use_analyst_endpoints`, `test_high_alert_waits_for_approval_then_executes` |
| T1 | Telemetry from agent A claims to be agent B | Collector credentials are scoped to `telemetry:write`; collectors are platform services whose identity is audited per batch. Agents emitting their own telemetry should be restricted at the gateway to their own `agent_id` | Audit `telemetry.ingest` actor |
| T2 | Baseline poisoning by repetition | Learning quarantine; MEDIUM+ events never learned; windows learned only when clean (ADR-0002) | `test_baseline_poisoning_is_resisted` |
| T3 | Tampering with alerts or audit | Optimistic concurrency on alerts; Ed25519 hash-chained audit per replica shipped to WORM storage | `test_audit_chain_is_signed_and_complete` |
| T4 | Rule or policy weakened | `CODEOWNERS` review; rules digest at `/v1/rules`; policy digest in every containment decision | Contract and rule-load tests |
| R1 | Analyst denies approving a suspension | Approver identity, note and policy digest in the audit chain and on the action | `test_audit_chain_is_signed_and_complete` |
| I1 | Secrets in telemetry leak through alerts or the SIEM | Excerpts scanned in memory, never stored; evidence lists finding kinds only | `test_telemetry_cannot_smuggle_instructions_or_secrets_into_outputs` |
| I2 | Alert data exposed to unauthorized readers | Analyst roles; agents need `threat:read` granted by the fabric | `test_scope_is_required_for_each_action` |
| D1 | Flooding ingestion | ≤ 1000 events per batch, ≤ 5000 spans, bounded fields; HPA; idempotent replays are cheap | `test_input_bounds` |
| D2 | Pathological regular expression in a rule | Rule review, 512-character pattern limit, 4096-character input cap, start-up validation | `test_rules_reject_pathological_patterns` |
| D3 | Containment abused to suspend critical agents | Protected-agent patterns always require approval; automatic only for critical and confident alerts; one action per agent; rollback | `test_policy_decisions_for_containment` |
| D4 | SIEM or fabric outage stops detection | Outbox decouples the SIEM; containment failure is recorded and retried; inbound authorization fails closed (503) by design | `tests/chaos/*` |
| E1 | Agent escalates through the detector's MCP/A2A tools | Per-tool authorization; containment requests from agents always need approval; delegated credentials cannot request containment | `test_delegated_agents_cannot_request_containment` |

## MITRE ATT&CK and ATLAS coverage of the detector itself

| Technique | Relevance | Control |
|---|---|---|
| T1078 Valid Accounts | Stolen collector credential | Short-lived fabric credentials, per-action authorization, audit |
| T1562 Impair Defenses | Disable or blind the detector | Telemetry-gap alert (`ThreatDetectionTelemetryStopped`), readiness probes, WORM audit |
| T1565 Data Manipulation | Poison baselines | Learning quarantine |
| T1499 Endpoint Denial of Service | Flood ingestion | Bounds, autoscaling, rate visibility |
| AML.T0051 LLM Prompt Injection | Injected text in telemetry tries to steer the detector | No LLM in the detection loop (ADR-0001); content is data |
| AML.T0020 Poison Training Data | Baseline learning is training | Learning quarantine, analyst-controlled learning |

## OWASP Top 10 for LLM Applications (2025)

| Risk | Position |
|---|---|
| LLM01 Prompt Injection | Detected in watched agents (`injection.content`, `injection.behavior_shift`); the detector itself runs no LLM |
| LLM02 Sensitive Information Disclosure | `exfiltration.credentials`, beacons; excerpts never persisted |
| LLM03 Supply Chain | Pinned dependencies with `uv.lock`, pip-audit, SBOM, Grype, provenance attestation |
| LLM04 Data and Model Poisoning | Learning quarantine for baselines |
| LLM05 Improper Output Handling | `exfiltration.markdown_beacon`, encoded-payload detection on agent output |
| LLM06 Excessive Agency | Core purpose: detects agents acting beyond their baseline; its own agency is bounded by policy and approval |
| LLM07 System Prompt Leakage | Injection detector flags system-prompt exfiltration phrasing in ingested content |
| LLM08 Vector and Embedding Weaknesses | Retrieval events (`content_ingest`) are scanned for injected instructions |
| LLM09 Misinformation | Not applicable to deterministic detection |
| LLM10 Unbounded Consumption | Rate-spike detection on agents; input bounds on the detector |

## OWASP API Security Top 10 (2023)

| Risk | Control |
|---|---|
| API1 Broken Object Level Authorization | Alerts and containment readable only by analyst roles or fabric-authorized `threat:read` |
| API2 Broken Authentication | Fabric introspection or JWKS verification; OIDC for analysts; no API keys |
| API3 Broken Object Property Level Authorization | Pydantic models with `extra="forbid"`; responses are explicit models |
| API4 Unrestricted Resource Consumption | Batch, span, field and excerpt limits |
| API5 Broken Function Level Authorization | Role per endpoint; approver role for containment |
| API6 Unrestricted Access to Sensitive Business Flows | Containment policy, one action per agent, separation of duties |
| API7 Server Side Request Forgery | Outbound URLs come only from configuration, never from requests |
| API8 Security Misconfiguration | Production refuses ephemeral keys and missing MCP host allow-list; non-root, read-only container |
| API9 Improper Inventory Management | OpenAPI and JSON Schemas generated and drift-checked in CI |
| API10 Unsafe Consumption of APIs | Fabric and SIEM responses validated; 5xx and invalid bodies fail closed |

## Threats to watched agents (what the detector looks for)

| Attack | ATT&CK / ATLAS | Detectors |
|---|---|---|
| Hijacked plan, compromised tool or plugin | AML.T0053 | `sequence.anomalous_window`, `sequence.novel_tool`, `atd-execution-shell-tool` |
| Prompt injection driving actions | AML.T0051 | `injection.content`, `injection.behavior_shift` |
| Permission probing and escalation | T1548, T1134, T1098 | `privilege.*`, `atd-iam-policy-change`, `atd-wildcard-scope-request` |
| Token misuse and delegation abuse | T1550 | `delegation.*`, `atd-token-exchange-storm` |
| Collection and exfiltration | T1213, T1030, T1041, T1048, T1567, AML.T0057 | `exfiltration.*`, `atd-restricted-bulk-read`, `atd-egress-paste-tunnel`, `atd-egress-destination-spray` |
| Credential theft | T1552 | `exfiltration.credentials`, `atd-credential-store-access` |
| Defense evasion | T1562 | `atd-audit-tampering` |

## Risk register

| ID | Risk | Likelihood | Impact | Treatment | Residual |
|---|---|---|---|---|---|
| R1 | False-positive automatic suspension interrupts a business process | Low | High | Critical-and-confident threshold, protected agents, report-only rollout, one-call rollback, false-positive verdict rolls back | Low |
| R2 | Slow, multi-day attacker below LOW thresholds becomes baseline | Low | High | Quarantine, Sigma rules independent of baselines, periodic baseline review via `/v1/profiles` | Medium |
| R3 | Fabric outage blocks telemetry (fail closed) | Medium | Medium | 30 s decision cache, fabric HA, page on `InboundAuthorizationFailing` | Low |
| R4 | Fleet behaviour differs from the synthetic benchmark | High | Medium | Report-only period with measured rates before automatic containment | Medium |
| R5 | Compromised collector forges telemetry | Low | Medium | Per-collector credentials, audit of every batch actor, gateway restriction of `agent_id` | Low |
| R6 | Containment client secret leaked | Low | High | Secret manager, read from file per refresh, rotation runbook, fabric audit of every suspension | Low |

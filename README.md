# Agent Threat Detection

Runtime threat detection for AI agent ecosystems. The service learns how each
agent normally behaves, detects the attack patterns specific to agents
(hijacked plans, prompt-injection-driven actions, permission probing,
delegation abuse, exfiltration, credential leaks), reports every finding to
the SIEM as an OCSF Detection Finding, and contains a compromised agent by
suspending it through the [agent identity fabric](https://github.com/kogunlowo123/agent-identity-fabric):
automatically for critical, high-confidence alerts, with human approval
otherwise, and always with one-call rollback.

```
Telemetry ─▶ Behavioural baseline ─▶ Detection ─▶ Scoring and dedup ─▶ SIEM (OCSF)
                                                           └─▶ Containment (identity fabric)
```

## Capabilities

| Capability | Implementation |
|---|---|
| Telemetry | Native agent events, agentic-core / identity-fabric audit events, OTLP/HTTP JSON traces (GenAI semantic conventions); idempotent by event id |
| Baselines | Per agent: session-aware n-gram Markov model with back-off, tool frequencies, per-transfer and per-window egress volume, 24-hour activity histogram, destinations, delegates, scopes, classification and delegation-depth ceilings |
| Behavioural detection | Anomalous sequence windows, novel tools (Good–Turing gated), rate spikes, off-hours activity, denial bursts, classification jumps, scope escalation, delegation cycles/depth/fan-out, new or external destinations, volume and drip exfiltration, credentials and URL beacons in egress, injected content and injection-triggered behaviour shifts |
| Rules | Sigma-style YAML (`rules/`): modifiers, boolean conditions, `count()` aggregations; mapped to MITRE ATT&CK and ATLAS |
| Scoring | Decayed per-agent risk, correlation, deduplication, learning quarantine against baseline poisoning, analyst feedback |
| SIEM | OCSF 1.3 Detection Findings (class 2004) through a transactional outbox to HTTP (OCSF array or Splunk HEC) or JSON Lines |
| Containment | `POST /v1/suspend` / `/v1/reinstate` on the identity fabric, decided by an agentic-core policy (`policies/containment.yaml`) with approval and rollback |
| Agent interfaces | MCP server at `/mcp` (streamable HTTP), A2A Agent Card and JSON-RPC `message/send` at `/a2a` |
| Security | Inbound calls authorized by the fabric (introspection plus `/v1/authorize`) or a local policy engine; analyst OIDC roles; signed audit chain |
| Observability | Prometheus metrics, OpenTelemetry traces, JSON logs with correlation ids, SLO alerts, Grafana dashboard |

Shared controls (policy engine, audit chain, injection and secret detection,
logging, telemetry) come from [agentic-core](https://github.com/kogunlowo123/agentic-core).

## Measured detection quality

On synthetic, labelled traces of 16 agents over 12 days with 64 injected
attack episodes across eight scenarios (default seed): **63 of 64 episodes
detected (98.4%)**, benign alert-level signals on **0.018% of benign events**
and on **4.2% of agent-days**. Results on three further seeds, per-scenario
time to detect and the method are in
[docs/architecture/detection-evaluation.md](docs/architecture/detection-evaluation.md).
These are benchmark numbers, not field numbers: run in report-only mode on
your own fleet before enabling automatic containment.

```bash
make evaluate
```

## Quick start (local)

Requires Docker. No API keys or cloud credentials are needed.

```bash
docker compose up --build
curl -s localhost:8080/.well-known/agent-card.json | jq '.skills[].id'
```

The compose stack runs the detector, the published identity-fabric image,
PostgreSQL, an OIDC provider standing in for the workload issuer, the
analysts' IdP and the client-credentials endpoint, and an OpenTelemetry
collector. It is a developer convenience and is not exercised in CI; the
container itself is smoke-tested in CI.

## Development

```bash
uv sync
make check        # ruff, black, mypy --strict, bandit, contracts, tests (coverage >= 90%)
make integration  # PostgreSQL tests (needs THREAT_TEST_DATABASE_URL)
make helm terraform
```

Test suites: `tests/unit` (including the measured detection-quality gates),
`tests/security` (adversarial cases mapped to the threat model),
`tests/chaos` (database, SIEM, fabric and audit failures), `tests/performance`
(throughput and latency budgets; `locustfile.py` for load), `tests/e2e`
(HTTP lifecycle, MCP, A2A, fabric mode, property-based OpenAPI contract) and
`tests/integration` (PostgreSQL).

## API

| Endpoint | Caller | Purpose |
|---|---|---|
| `POST /v1/events` | Collector / agent (`telemetry:write`) | Batch of native events |
| `POST /v1/events/audit` | Collector (`telemetry:write`) | agentic-core / identity-fabric audit events |
| `POST /v1/traces` | OTel collector (`telemetry:write`) | OTLP/HTTP JSON trace export |
| `GET /v1/alerts`, `GET /v1/alerts/{id}` | Analyst roles | Alerts |
| `POST /v1/alerts/{id}/acknowledge`, `/resolve` | `threat-analyst` | Triage, verdicts (false positives teach the baseline) |
| `GET /v1/profiles?agent_id=` | Analyst roles | Baseline summary and risk |
| `GET /v1/rules` | Analyst roles | Loaded rules and their digest |
| `GET /v1/containment`, `GET /v1/containment/{id}` | Analyst roles | Containment actions |
| `POST /v1/containment/{id}/approve`, `/reject`, `/rollback` | `containment-approver` | Human decisions |
| `/mcp` | Agents (fabric credential) | MCP tools `list_alerts`, `get_agent_risk`, `submit_events`, `request_containment` |
| `GET /.well-known/agent-card.json`, `POST /a2a` | Agents | A2A skills `triage-agent`, `ingest-telemetry`, `request-containment` |
| `/healthz`, `/readyz`, `/metrics` | Platform | Operations |

Full contract: [docs/api/openapi.json](docs/api/openapi.json); JSON Schemas in [schemas/](schemas/).

## Deployment

| Layer | Location |
|---|---|
| Container image | `Dockerfile` (non-root, read-only root filesystem compatible) |
| Helm chart | `deployments/helm/agent-threat-detection` (StatefulSet, PDB, HPA, NetworkPolicy, ServiceMonitor, Ingress) |
| Namespace and secret sync | `deployments/kubernetes` (restricted Pod Security, External Secrets) |
| Cloud infrastructure | `deployments/terraform/{aws,azure,gcp}`: managed PostgreSQL, KMS, secret manager, WORM storage for audit and findings, workload identity. AWS is the reference deployment |

See the [startup runbook](docs/runbooks/startup.md).

## Documentation

- [Architecture](docs/architecture/overview.md), [agent specification](docs/architecture/agent-specification.md), [detection evaluation](docs/architecture/detection-evaluation.md)
- [ADRs](docs/architecture/adr/)
- [Threat model and risk register](docs/security/threat-model.md)
- [Compliance control mapping](docs/compliance/control-mapping.md)
- Runbooks: [startup](docs/runbooks/startup.md), [monitoring](docs/runbooks/monitoring.md), [incident response](docs/runbooks/incident-response.md), [containment](docs/runbooks/containment.md), [rollback](docs/runbooks/rollback.md), [disaster recovery](docs/runbooks/disaster-recovery.md)
- [Configuration reference](docs/operations/configuration.md)

## License

Apache-2.0

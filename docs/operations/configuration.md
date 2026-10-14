# Configuration reference

All settings are `THREAT_*` environment variables (see
`src/agent_threat_detection/config.py`). Nested detection settings use a
double underscore, e.g. `THREAT_DETECTION__BASELINE_MIN_EVENTS=1000`. The
service refuses to start with incomplete or inconsistent configuration.

## Service

| Variable | Required | Default | Description |
|---|---|---|---|
| `THREAT_ENVIRONMENT` | no | `production` | `production` forbids ephemeral keys and requires `THREAT_MCP_ALLOWED_HOSTS` |
| `THREAT_PUBLIC_URL` | yes | | Public base URL; the A2A card advertises `<url>/a2a` |
| `THREAT_DATABASE_URL` | yes | | SQLAlchemy async URL (`postgresql+asyncpg://...`) |
| `THREAT_AUDIT_KEY_FILE` | yes* | | Ed25519 PEM; the file stem is the audit key id |
| `THREAT_DEV_EPHEMERAL_KEYS` | no | `false` | In-memory audit key, non-production only (replaces *) |
| `THREAT_AUDIT_LOG_PATH` | no | `/var/lib/agent-threat-detection/audit/audit.jsonl` | Audit chain file (per replica) |
| `THREAT_MCP_ALLOWED_HOSTS` | production | `[]` | JSON list of `Host` values accepted on `/mcp` |
| `THREAT_LOG_LEVEL` | no | `INFO` | |
| `THREAT_OTLP_ENDPOINT` | no | | OTLP gRPC endpoint for the detector's own traces |
| `THREAT_HOST` / `THREAT_PORT` | no | `127.0.0.1` / `8080` | The image sets host `0.0.0.0` |
| `THREAT_FORWARDED_ALLOW_IPS` | no | `127.0.0.1` | Proxies trusted for `X-Forwarded-*` |
| `THREAT_PROCESSED_EVENT_RETENTION_HOURS` | no | `48` | How long event ids are kept for idempotency |

## Analysts (enterprise OIDC)

| Variable | Required | Default | Description |
|---|---|---|---|
| `THREAT_ANALYST_ISSUER` | yes | | Issuer of analyst tokens |
| `THREAT_ANALYST_AUDIENCE` | yes | | Required audience |
| `THREAT_ANALYST_JWKS_URL` | yes | | JWKS of the IdP |
| `THREAT_ANALYST_ROLES_CLAIM` | no | `roles` | Claim with `threat-analyst`, `containment-approver`, `detection-engineer` |

## Identity fabric

| Variable | Required | Default | Description |
|---|---|---|---|
| `THREAT_FABRIC_URL` | yes** | | Base URL of the agent identity fabric |
| `THREAT_FABRIC_TOKEN_URL` | for containment | | IdP token endpoint for the client-credentials grant |
| `THREAT_FABRIC_CLIENT_ID` | for containment | | Client whose tokens carry `agent-security-officer` |
| `THREAT_FABRIC_CLIENT_SECRET_FILE` | for containment | | File holding the client secret (read on each refresh) |
| `THREAT_FABRIC_TOKEN_SCOPE` | no | | e.g. `api://identity-fabric/.default` on Entra ID |
| `THREAT_AUTHORIZATION_CACHE_SECONDS` | no | `30` | Allow-decision cache, 0–300 s, never beyond token expiry |

The three containment settings are set together or not at all. Without
them, inbound calls are still authorized by the fabric, but containment
actions are recorded as `failed` (no lifecycle client).

** Without `THREAT_FABRIC_URL`, local authorization is used and these are required:

| Variable | Description |
|---|---|
| `THREAT_AGENT_JWKS_URL` | JWKS of the agent credential issuer (normally the fabric's `/.well-known/jwks.json`) |
| `THREAT_AGENT_ISSUER` | Expected `iss` |
| `THREAT_AGENT_AUDIENCE` | Expected `aud` |
| `THREAT_INBOUND_POLICY_FILE` | Local policy (default `policies/inbound-authorization.yaml`) |

## Detection and response

| Variable | Default | Description |
|---|---|---|
| `THREAT_RULES_DIR` | `rules` | Directory of Sigma-style YAML rules |
| `THREAT_CONTAINMENT_POLICY_FILE` | `policies/containment.yaml` | Containment policy |
| `THREAT_AUTO_CONTAINMENT` | `true` | Allow automatic suspension for critical, confident alerts |
| `THREAT_PROTECTED_AGENTS` | `[]` | JSON list of SPIFFE glob patterns only a human may contain |
| `THREAT_DETECTION__INTERNAL_DOMAIN_SUFFIXES` | `[]` | JSON list of internal DNS suffixes; egress elsewhere is external |
| `THREAT_DETECTION__BASELINE_MIN_EVENTS` | `500` | Learned events before statistical detectors arm |
| `THREAT_DETECTION__BASELINE_MIN_HOURS` | `72` | Hours of history before statistical detectors arm |
| `THREAT_DETECTION__QUARANTINE_DAYS` | `3` | Distinct days a LOW anomaly must recur before it is learned |
| `THREAT_DETECTION__SEQUENCE_WINDOW` | `8` | Steps in the sequence-surprise window |
| `THREAT_DETECTION__SEQUENCE_WINDOW_ZSCORE` | `5.0` | Alert threshold for the window |
| `THREAT_DETECTION__NOVELTY_MISSING_MASS` | `0.02` | Good–Turing threshold for alert-level novelty |
| `THREAT_DETECTION__DENIAL_BURST_COUNT` | `5` | Denials within `DENIAL_BURST_WINDOW_S` (300) |
| `THREAT_DETECTION__EGRESS_ZSCORE_MEDIUM` / `_HIGH` | `4.0` / `6.0` | Per-transfer volume thresholds |
| `THREAT_DETECTION__EGRESS_WINDOW_S` | `900` | Tumbling window for drip detection |
| `THREAT_DETECTION__RISK_ALERT_THRESHOLD` | `0.8` | Accumulated risk that raises `risk.threshold` |
| `THREAT_DETECTION__RISK_HALF_LIFE_S` | `3600` | Risk decay |
| `THREAT_DETECTION__DEDUP_WINDOW_S` | `3600` | Alert deduplication window |
| `THREAT_DETECTION__SUPPRESSION_DAYS` | `30` | Suppression after a false-positive verdict |

Every field of `DetectionConfig` (`src/agent_threat_detection/detection/config.py`)
can be set this way. Changing thresholds changes measured rates: re-run
`make evaluate` and update `docs/architecture/detection-evaluation.md`.

## SIEM

| Variable | Default | Description |
|---|---|---|
| `THREAT_SIEM_MODE` | `file` | `http` or `file` |
| `THREAT_SIEM_URL` | | Collector URL (required for `http`) |
| `THREAT_SIEM_FORMAT` | `ocsf` | `ocsf` (JSON array, bearer) or `splunk_hec` |
| `THREAT_SIEM_TOKEN_FILE` | | Token file (read on each delivery) |
| `THREAT_SIEM_FILE_PATH` | `/var/lib/agent-threat-detection/findings/ocsf.jsonl` | JSON Lines output for `file` |
| `THREAT_SIEM_INTERVAL_SECONDS` | `5` | Outbox polling interval |

## OTLP attribute mapping (`POST /v1/traces`)

| Span attribute | Event field |
|---|---|
| `agent.id` or `gen_ai.agent.id` (span or resource) | `agent_id` (SPIFFE; spans without one are skipped) |
| `gen_ai.operation.name` | `kind`: `execute_tool`→tool_call, `chat`/`text_completion`/`generate_content`/`embeddings`→model_call, `invoke_agent`→delegation, `retrieve`→content_ingest, `data_transfer`, `authorize` |
| `gen_ai.tool.name` | `tool` |
| `agent.action` | `action` (defaults to the tool or operation) |
| `agent.resource` | `resource` |
| `server.address` | `destination` |
| `agent.egress.bytes` | `bytes_out` |
| `agent.data.classification` | `classification` (0–3) |
| `agent.delegate.id`, `agent.delegation.chain` | `delegate`, `delegation_chain` |
| `agent.scopes.requested` | `scopes_requested` |
| `agent.content.excerpt`, `agent.injection.score` | content checks (never stored) |
| `agent.authorization.decision` | outcome for `authorize` spans |
| `gen_ai.conversation.id` | `session_id` |
| span status code 2 | outcome `failure` |

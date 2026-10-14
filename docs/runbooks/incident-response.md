# Runbook: incident response

## Critical alert

`CriticalAgentThreat` fires when any critical alert is open.

1. Open the alert: `GET /v1/alerts?min_severity=critical` (role
   `threat-analyst`). Read `detector`, `rule_id`, `techniques` and `evidence`.
2. Check containment: `alert.status == "contained"` means the agent is
   already suspended through the identity fabric; `containment_id` links the
   action and its policy digest.
3. If not contained (protected agent, low confidence, automatic containment
   off), decide using the [containment runbook](containment.md).
4. Pull the agent's context: `GET /v1/profiles?agent_id=...` shows its
   baseline (top tools, destinations, delegates, classification ceiling) and
   current risk. Compare the evidence with the baseline.
5. Search the SIEM for the OCSF finding (`finding_info.uid` = alert id) and
   related telemetry around `first_seen_time`.
6. For `injection.behavior_shift`, the evidence field `injected_event_id`
   identifies the content the agent ingested; quarantine that source (page,
   document, tool output) with the owning team.
7. For `exfiltration.credentials`, rotate the exposed credential type listed
   in `secret_kinds` immediately; the value itself is never stored here.
8. Resolve: `POST /v1/alerts/{id}/resolve` with `true_positive` and a note
   referencing the incident ticket.

## False positive

Resolve with `false_positive`. This suppresses the alert key for 30 days,
adds the evidence to the agent's baseline and, if the agent was suspended,
reinstates it through the fabric. The verdict is audited with your identity.

## Service degraded

`ThreatDetectionErrorBudgetBurnFast`.

1. `kubectl -n agent-security get pods`; check readiness (`/readyz` checks
   the database).
2. Logs: `kubectl logs ... | grep -i error`.
3. Database unreachable: follow the database provider's failover; the
   service recovers automatically once `/readyz` passes.
4. Recent release: follow [rollback](rollback.md).

## Fabric unreachable

`InboundAuthorizationFailing`: telemetry is refused with 503 because the
detector cannot authorize callers (fail closed). Collectors buffer and retry.

1. Check the identity fabric's own health and its runbooks.
2. Check NetworkPolicy egress and DNS from the `agent-security` namespace.
3. Containment actions attempted meanwhile are recorded as `failed` and need
   approval again once the fabric is back.

## Compromise of the detector itself

If the detector's fabric client secret or audit key may be exposed:

1. Rotate the client secret at the IdP, update the secret manager entry; the
   new value is read on the next token refresh.
2. Review fabric audit events for `agent.suspended` / `agent.active` actions
   by the detector's client and reverse any not matching a containment
   record here.
3. Generate a new audit key with a new id, update the secret, restart the
   pods, and keep the old public key for verifying earlier chains.

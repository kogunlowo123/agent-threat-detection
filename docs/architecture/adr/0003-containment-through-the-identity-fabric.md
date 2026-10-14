# ADR-0003: Containment through the identity fabric, gated by policy and approval

- Status: Accepted
- Date: 2026-10-14

## Context

A detector that can only alert leaves a compromised agent running while
humans react. A detector that can kill workloads directly needs cluster
privileges, behaves differently on every runtime, and becomes a high-value
target. Agents in this platform obtain every credential from the agent
identity fabric, which already supports suspension with immediate effect
(credential epochs invalidate all outstanding tokens, including delegated
ones) and reinstatement.

## Decision

- Containment is `POST /v1/suspend?agent_uri=...` on the fabric through a
  typed client, authenticated with an enterprise-IdP client-credentials token
  that carries the fabric's `agent-security-officer` role. Rollback is
  `POST /v1/reinstate`. The detector never revokes agents.
- Every containment goes through `policies/containment.yaml` on the
  agentic-core `PolicyEngine`:
  - deny below HIGH severity;
  - require approval for protected agents, agent-requested containment, HIGH
    alerts, CRITICAL alerts below 0.9 confidence, and whenever automatic
    containment is switched off;
  - allow automatically only for CRITICAL alerts with confidence of at least
    0.9, requested by the detector itself.
- One active action per agent; later alerts attach to it.
- The requester cannot approve its own request. Approval executes, and a
  failed execution can be retried by approving again.
- A false-positive verdict on a contained alert rolls the suspension back.

## Consequences

- Containment works the same on every runtime because it acts on identity,
  not on pods: the agent keeps running but cannot obtain or use credentials.
- The policy digest of every decision is in the audit chain, so a reviewer
  can prove which policy suspended which agent.
- If the fabric is unreachable, containment is recorded as `failed`, pages
  on-call, and can be retried; detection and alerting continue.

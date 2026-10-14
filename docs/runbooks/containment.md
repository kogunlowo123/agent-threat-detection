# Runbook: containment

Containment suspends an agent through the identity fabric
(`POST /v1/suspend`). Suspension bumps the agent's credential epoch, so every
outstanding credential, including delegated ones, stops validating at the
next check. The agent's workload keeps running but cannot act.

## States

```
pending_approval --approve--> executed --rollback--> rolled_back
        |                       ^
        +--reject--> rejected   |
        +--approve (fabric down)--> failed --approve (retry)--+
```

Automatic actions start at `executed` (or `failed`).

## Approve

`ContainmentAwaitingApproval` pages after 15 minutes.

1. `GET /v1/containment?status=pending_approval` (any analyst role).
2. Read the linked alert (`alert_id`) and the policy rules that required
   approval (`matched_rules`: `approve-high`, `approve-protected-agents`,
   `approve-agent-requested`, `approve-critical-low-confidence`,
   `approve-when-auto-disabled`).
3. For protected (tier-0) agents, confirm with the owning platform team
   before suspending: suspending the identity fabric's own agents, CI
   agents or security tooling can have wide impact.
4. Approve with role `containment-approver`:

```bash
curl -X POST "$ATD/v1/containment/$ID/approve" -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' -d '{"note": "INC-1234: confirmed exfiltration"}'
```

The requester of an action cannot approve it. Approval executes immediately.

## Reject

`POST /v1/containment/{id}/reject` with a note. The alert stays open for
analyst resolution.

## Failed

`ContainmentFailed` pages immediately. `error` on the action says why
(fabric unreachable, agent unknown to the fabric, IdP refused client
credentials). Fix the cause, then approve the same action again to retry;
`attempts` increments.

## Roll back

`POST /v1/containment/{id}/rollback` (role `containment-approver`) calls
`POST /v1/reinstate` on the fabric. Marking the alert `false_positive` does
the same automatically. The agent must obtain new credentials after
reinstatement; old ones stay invalid because of the epoch change.

## Emergency: stop automatic containment

Set `detector.autoContainment: false` and upgrade the release (or set
`THREAT_AUTO_CONTAINMENT=false`). Every new containment then waits for
approval; existing actions are unaffected.

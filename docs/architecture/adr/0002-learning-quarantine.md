# ADR-0002: Learning quarantine against baseline poisoning

- Status: Accepted
- Date: 2026-10-14

## Context

Behavioural baselines learn continuously so that agents can evolve. That
makes them a target: an attacker who repeats a behaviour can teach the
baseline that it is normal. The first measurement run of the evaluation
benchmark showed exactly this. A hijacked tool sequence repeated twice was
learned on its first pass and looked familiar on the second, and slow "drip"
transfers inflated the egress statistics until the drip itself fell inside
the normal range.

## Decision

- Events without anomaly signals are learned immediately.
- Events whose worst signal is LOW are quarantined: their anomaly keys are
  recorded per day, and the event is learned only once every key has recurred
  on `quarantine_days` (default 3) distinct days without ever producing a
  MEDIUM or higher signal.
- Events with MEDIUM or higher signals are never learned.
- Per-window egress statistics learn a window only after it closes, and only
  if no alert-level signal occurred in it.
- Analyst false-positive verdicts are the explicit path for teaching the
  baseline quickly: the alert key is suppressed for 30 days and its evidence
  (destination, delegate, tool, classification, scopes) is added to the profile.

## Consequences

- A campaign must persist for several days at low intensity, without ever
  tripping an alert-level detector, before it becomes normal. The security
  test `test_baseline_poisoning_is_resisted` covers 50 repetitions.
- Legitimate new behaviour that trips only LOW signals takes three days to
  become quiet; analysts can shortcut that with a false-positive verdict,
  which is audited.

# ADR-0005: Session-aware sequence windows and Good–Turing novelty gating

- Status: Accepted
- Date: 2026-10-14

## Context

Two findings from the evaluation benchmark drove this decision.

1. Single rare transitions are common in benign traces. With limited support
   one cannot claim with confidence that a transition is below 1%, and real
   agents do take unusual steps. Alerting on single transitions produced most
   of the false positives in the first measurement run.
2. Agents run concurrent sessions. Modelling one interleaved stream per agent
   scrambles the context, so benign steps that follow another session's steps
   look improbable.

Novelty detectors (new tool, destination, delegate) had a related problem:
right after the baseline matured, legitimately rare items were still being
seen for the first time.

## Decision

- Transition counts are shared per agent, but the context history is kept per
  session (`session_id`, capped at 256 sessions per agent).
- Single rare transitions are LOW evidence that does not add to risk. The
  alerting sequence detector scores the mean surprise of a session's last 8
  steps against an exponentially weighted mean and deviation of the agent's
  per-step surprise (z of at least 5): a run of improbable steps is what marks
  a hijacked plan.
- Novelty is alert-level only when the Good–Turing missing-mass estimate,
  (singletons + 1) / (observations + 1), is below 0.02, meaning the agent's
  vocabulary has settled; otherwise it is LOW. Egress to a destination outside
  `internal_domain_suffixes` is alert-level regardless.

## Consequences

- Across the six-episode benchmark runs that introduced these two changes,
  benign alert events fell from 145 to 22 and rare-sequence detection reached
  6 of 6 episodes (from 2 of 6 with the window detector on interleaved
  sessions). The documented configuration detects 8 of 8.
- Telemetry without session ids still works as one shared stream but loses
  this protection; the OTLP mapping uses `gen_ai.conversation.id`.

# ADR-0001: Deterministic statistical and rule-based detection, no LLM in the detection loop

- Status: Accepted
- Date: 2026-10-14

## Context

The telemetry this service inspects is produced by AI agents and often
contains text those agents ingested from untrusted sources. An LLM that
reads that telemetry to decide whether it is malicious would itself be a
prompt-injection target: an attacker who can make an agent fetch a page can
also make the detector read it. Detection also has to be fast (every tool
call), explainable to an analyst, reproducible for audit, and cheap enough
to run on every event.

## Decision

- Detection uses per-agent statistics (Markov sequence model, frequency and
  volume moments, histograms, Good–Turing novelty) and Sigma-style rules.
  Every signal carries the statistic and threshold that produced it.
- Content checks reuse agentic-core's deterministic `PromptInjectionDetector`
  and `SecretScanner`; content excerpts are inspected in memory and never
  stored or forwarded.
- No model provider is configured, so there is no `configs/providers.yaml`.
- An LLM triage assistant, if added later, sits downstream of findings,
  reads only structured alert fields, and cannot change detection outcomes.

## Consequences

- Detection quality is measurable and reproducible
  ([detection-evaluation.md](../detection-evaluation.md)); the same input
  always yields the same alerts.
- There is no per-event inference cost and no dependency on model availability.
- Novel attack classes need a new detector or rule rather than being
  "understood" by a model; the rule format makes adding them a reviewable,
  testable change.

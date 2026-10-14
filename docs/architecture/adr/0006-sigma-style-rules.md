# ADR-0006: A Sigma-style rule subset evaluated in process

- Status: Accepted
- Date: 2026-10-14

## Context

Security teams already write and review detections as Sigma rules, and a
detection engineer should be able to add an agent-specific rule without a
code change. Full Sigma is a large language with backends for many query
languages; here it has to be evaluated per event inside the detector.

## Decision

- Rules use the Sigma layout with `logsource.product: agent` and
  `logsource.category` set to an event kind. Supported: field modifiers
  `contains`, `startswith`, `endswith`, `re`, `gt`, `gte`, `lt`, `lte`,
  `exists`, `all`, `cased`; wildcards with escaping; selections as maps or
  lists of maps; conditions with `and`, `or`, `not`, parentheses, `1 of`,
  `all of` and `them`; Sigma v1 `count()` and `count(field)` aggregations
  with `by` and a `timeframe`.
- Rules are parsed and validated at start-up; an invalid rule stops the
  service. Regular expressions are limited to 512 characters and matched
  against at most 4096 characters of a field.
- The string alternatives of one field compile into a single case-insensitive
  regular expression, which cut rule-evaluation time by about 45% on the benchmark.
- Aggregation state lives in the agent's profile, so every aggregation is
  scoped to one agent.
- Tags `attack.tNNNN` and `atlas.aml.tNNNN` map to ATT&CK and ATLAS techniques
  in alerts and OCSF findings.

## Consequences

- Rules are data: reviewed through `CODEOWNERS`, versioned, and identified by
  a digest exposed at `GET /v1/rules`.
- Sigma features outside the subset (keyword lists, `near`, correlation
  rules, value modifiers such as `base64offset`) are rejected at load time
  rather than silently ignored.

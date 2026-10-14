# Detection evaluation

Measured on synthetic, labelled agent telemetry produced by
`agent_threat_detection.evaluation.simulator` and scored by
`agent_threat_detection.evaluation.metrics`. Reproduce with:

```bash
uv run python -m agent_threat_detection.evaluation --agents 16 --days 12 --episodes 8 --seed 20261014
```

The regression gates in `tests/unit/test_detection_quality.py` run the
default seed and an unseen seed on every CI build.

## How the traces are built

**Benign agents.** Sixteen agents drawn from four personas (support, finance,
DevOps, research), each with its own tool set plus retrieval and egress
tools. Each tool has three successors with probabilities 0.65 / 0.25 / 0.10
and a 1% uniform jump, so benign traces contain genuinely rare transitions.
Six to ten sessions a day of 6–20 steps, 3% of sessions off-hours,
log-normal egress volumes to three internal destinations, occasional
delegation to two workers, and a 0.4% benign authorization-denial rate. Every
tool call is preceded by an authorization event. Sessions run concurrently
and carry session ids.

**Attack episodes.** After a four-day baseline, eight episodes of each
scenario are injected at random times into random agents' timelines, and
every attack event is labelled:

| Scenario | What the attacker does |
|---|---|
| `rare_tool_sequence` | A hijacked plan walks the agent's own tools in an order it never uses (twice) |
| `privilege_escalation` | Eight denied IAM/secret actions, then a credential request for `iam:admin` and `*` |
| `delegation_abuse` | Six delegations to unknown relay agents with a growing chain |
| `exfiltration_bulk` | Sensitive read, then one transfer ~e^(7σ+3) above normal to an external host |
| `exfiltration_drip` | Sixty transfers at ~2.5σ to a *known* internal destination within ~10 minutes |
| `credential_leak` | Outbound content carrying an AWS access key id |
| `injection_shift` | Retrieved page with injected instructions, then a transfer to the attacker's host |
| `defense_evasion` | `cloudtrail:StopLogging` |

## Definitions

- **Episode detected**: at least one alert-level signal (MEDIUM or higher,
  not suppressed) on one of its events.
- **Events to detect**: episode events up to and including the first detecting event.
- **Benign alert rate**: share of benign events that produced an alert-level signal.
- **Benign agent-day alert rate**: share of (agent, day) pairs after baseline
  maturity on which any benign event produced an alert-level signal.

## Results (default configuration, 16 agents, 12 days, 8 episodes per scenario)

| Seed | Events | Detection rate | Benign alert events | Benign alert rate | Agent-days with a benign alert |
|---|---|---|---|---|---|
| 20261014 (default) | 40,285 | 63/64 (98.4%) | 7 | 0.018% | 6/144 (4.2%) |
| 1 | 43,516 | 64/64 (100%) | 2 | 0.005% | 2/144 (1.4%) |
| 2 | 39,398 | 63/64 (98.4%) | 8 | 0.021% | 6/144 (4.2%) |
| 3 | 41,921 | 63/64 (98.4%) | 16 | 0.039% | 10/144 (6.9%) |

Per scenario on the default seed:

| Scenario | Detected | Mean events to detect | First detectors |
|---|---|---|---|
| rare_tool_sequence | 8/8 | 7.75 | `sequence.anomalous_window` (7), `sequence.novel_tool` (1) |
| privilege_escalation | 8/8 | 3.0 | `sigma` (wildcard scope / IAM rules) |
| delegation_abuse | 8/8 | 2.5 | `delegation.depth` (6), `delegation.new_delegate` (2) |
| exfiltration_bulk | 8/8 | 2.0 | `exfiltration.new_destination`, `exfiltration.volume`, `exfiltration.window_volume` |
| exfiltration_drip | 7/8 | 7.6 | `sequence.anomalous_window` (6), `exfiltration.window_volume` (2) |
| credential_leak | 8/8 | 1.0 | `exfiltration.credentials` |
| injection_shift | 8/8 | 2.0 | `injection.behavior_shift` (critical/high), `exfiltration.new_destination` |
| defense_evasion | 8/8 | 1.0 | `sigma` (`atd-audit-tampering`), `sequence.novel_tool` |

Benign alerts on the default seed came from `sequence.anomalous_window` (5)
and `sequence.novel_tool` (2): agents legitimately using a rarely reachable
tool for the first time after the baseline matured, and sessions with
several 1% jumps in a row.

The one recurring miss is drip exfiltration from agents whose egress history
is too short for the per-window statistics (fewer than 30 completed windows)
and whose drip happens not to look sequentially unusual. Longer baselines
remove it; the simulator's four-day baseline is deliberately short.

## Throughput

About 0.35 ms per event single-threaded with every detector and the nine
repository rules enabled (40,285 events in roughly 14 s of detection time
on a developer workstation, uninstrumented). The CI performance test gates a
looser budget because it runs under coverage tracing.

## What the numbers do and do not show

They show that the detectors separate the modelled attacks from the modelled
benign behaviour, that the thresholds are not tuned to one random seed, and
that design choices such as session-aware sequence windows and the learning
quarantine matter (both were added after measurements on this benchmark
showed interleaved sessions and immediate learning causing false positives
and missed detections). They do not show performance on any real agent
fleet: real tool vocabularies, session structure and attacker behaviour will
differ. Before enabling automatic containment in production, run the
detector in report-only mode (`THREAT_AUTO_CONTAINMENT=false`) against real
telemetry, review alerts for at least two weeks, and record the measured
rates for that fleet.

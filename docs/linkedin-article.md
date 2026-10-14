An AI agent with valid credentials can still be working for someone else. A poisoned web page, a compromised tool or a stolen token produces activity that passes every authorization check.

The problem: identity tells us what an agent may do, not whether it is behaving like itself. SOC teams have EDR for hosts and UEBA for users; for agents they mostly have logs.

Why it matters: agents read regulated data, delegate to other agents and send data out. The window between hijack and damage is a few tool calls.

The flow we built: Telemetry (audit events, OTLP spans) → Behavioural baseline per agent → Detection (statistics plus Sigma-style rules) → Scoring and dedup → SIEM as OCSF findings → Containment through the identity fabric → Observability.

Implementation steps:
1. Normalize agent telemetry into one event model.
2. Learn per-agent baselines: session-aware Markov sequences, egress volume per transfer and per window, hours, destinations, delegates.
3. Detect runs of improbable steps, denial bursts, delegation cycles, new external destinations, secrets in egress, and behaviour shifts right after injected content.
4. Gate containment with policy: automatic only for critical, high-confidence alerts; human approval otherwise; one-call rollback.
5. Measure detection and false-positive rates on labelled synthetic traces in CI.

Best practices: no LLM in the detection loop, since it would be an injection target. Quarantine anomalies before learning them so attackers cannot teach the baseline. Fail closed when authorization is unavailable. Deliver findings through an outbox. Sign every decision.

Risks and tradeoffs: statistical baselines need days of history; benchmark rates are not fleet rates; automatic suspension can interrupt a business process; per-agent state adds database cost. OCSF and Sigma-style rules limit lock-in.

Business value: faster containment, evidence auditors can verify, and one place for detection engineers to add agent-specific rules.

Future relevance: as agents delegate to agents, behaviour becomes the control plane for trust.

Question: should a detector ever suspend an agent without a human, or is approval always worth the delay?

Code: https://github.com/kogunlowo123/agent-threat-detection

#AI #ArtificialIntelligence #GenerativeAI #AgenticAI #LLMOps #EnterpriseAI #AISecurity #RAG #MachineLearning #DataScience #CloudComputing #Kubernetes #MLOps #DigitalTransformation #Innovation #ThreatDetection #SecurityOperations #OCSF

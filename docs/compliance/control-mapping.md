# Compliance control mapping

How the detector supports common control frameworks. It provides technical
evidence; the operating organization owns the controls.

## SOC 2 (2017 Trust Services Criteria)

| Criterion | Support |
|---|---|
| CC6.1 Logical access | Agent credentials authorized by the identity fabric per action; analyst OIDC with RBAC |
| CC6.6 Boundary protection | NetworkPolicy default deny; egress limited to database, HTTPS dependencies and OTLP |
| CC6.8 Malicious software | Detection of agents executing shell tools, tampering with audit, exfiltrating data |
| CC7.2 Monitoring for anomalies | Per-agent behavioural baselines and rules on every event; OCSF findings to the SIEM |
| CC7.3 Evaluate security events | Deduplicated alerts with severity, confidence, ATT&CK/ATLAS techniques and evidence; analyst workflow |
| CC7.4 Respond to incidents | Policy-gated containment through the identity fabric, approval, rollback, runbooks |
| CC8.1 Change management | Rules and policies under code review (`CODEOWNERS`), digests recorded with decisions, CI gates |

## ISO/IEC 27001:2022 Annex A

| Control | Support |
|---|---|
| A.5.7 Threat intelligence | Rules tagged with ATT&CK and ATLAS techniques |
| A.5.24–A.5.26 Incident management | Alerts, containment, runbooks, audit trail |
| A.5.28 Collection of evidence | Hash-chained, signed audit events on WORM storage; OCSF findings with evidence ids |
| A.8.15 Logging | Audit chain, structured logs with correlation ids |
| A.8.16 Monitoring activities | Behavioural monitoring of every agent |
| A.8.12 Data leakage prevention | Exfiltration detectors and credential scanning of agent egress |
| A.8.2 Privileged access rights | Containment authority isolated in one client, approval for high-impact actions |

## NIST SP 800-53 Rev. 5

| Control | Support |
|---|---|
| AU-2, AU-3, AU-9, AU-10 | Event content, protection and non-repudiation of the audit chain |
| AU-6 Audit review, analysis and reporting | Findings to the SIEM in OCSF |
| CA-7 Continuous monitoring | Continuous behavioural detection |
| IR-4 Incident handling, IR-5 Incident monitoring | Alert and containment lifecycle |
| SI-4 System monitoring | Core function; SI-4(2) automated tools, SI-4(4) inbound and outbound traffic (agent egress), SI-4(24) indicators of compromise via rules |
| AC-2(12) Account monitoring for atypical usage | Per-agent baselines for non-human identities |
| AC-6 Least privilege | Detector scopes; approval for containment beyond the policy threshold |
| SC-7 Boundary protection | NetworkPolicy, private database endpoints |

## NIST AI Risk Management Framework (AI RMF 1.0)

| Function | Support |
|---|---|
| GOVERN 1.4, 2.1 | Documented roles (analyst, approver, engineer), containment policy as code |
| MAP 4.1, 5.1 | Threat model mapping agent-specific risks (ATLAS, OWASP LLM Top 10) |
| MEASURE 2.6, 2.7 | Measured detection and false-positive rates on labelled traces; security of the detector itself tested |
| MEASURE 3.1, 4.1 | Continuous monitoring of deployed agents; analyst feedback recorded |
| MANAGE 2.4, 4.1 | Ability to disengage (suspend) an agent quickly, with rollback; post-deployment monitoring |

## HIPAA Security Rule (where agents handle PHI)

| Standard | Support |
|---|---|
| 164.308(a)(1)(ii)(D) Information system activity review | Alerts and findings on agent activity, including bulk reads of RESTRICTED data |
| 164.308(a)(6) Security incident procedures | Containment and incident-response runbooks |
| 164.312(b) Audit controls | Signed audit chain; telemetry content never stored |

## EU AI Act (where watched agents are high-risk systems)

| Article | Support |
|---|---|
| Art. 12 Record-keeping | Event-level records of agent actions through telemetry and findings |
| Art. 14 Human oversight | Human approval for every non-critical containment and every agent-requested containment; rollback |
| Art. 15 Accuracy, robustness, cybersecurity | Runtime detection of manipulation (prompt injection, poisoning, exfiltration) |

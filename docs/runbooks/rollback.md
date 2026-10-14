# Runbook: release rollback

## Application

```bash
helm -n agent-security history atd
helm -n agent-security rollback atd <revision> --wait
kubectl -n agent-security rollout status statefulset/atd-agent-threat-detection
curl -sf "$ATD/readyz"
```

The database schema is additive within a minor version (`schema_version`
table); rolling back the application does not require a database rollback.
Profiles written by a newer patch version load in the older one because
unknown fields are ignored by Pydantic.

## Detection rules or thresholds

Rules ship in the image (`/app/rules`). A bad rule fails start-up, so a
rollout with an invalid rule never becomes ready and the previous pods keep
serving. A rule that produces too many alerts:

1. Roll back the release, or
2. Resolve the noisy alerts as `false_positive` (this suppresses each key
   for 30 days) while a fixed rule is reviewed.

Threshold changes (`THREAT_DETECTION__*`) take effect on restart and are
rolled back the same way as configuration.

## Containment policy

`policies/containment.yaml` ships in the image; the policy digest of each
decision is in the audit chain. Roll back the release to restore the
previous policy; review decisions made under the bad policy by filtering the
audit chain on its digest.

## Image verification

Release images carry SLSA provenance attestations:

```bash
gh attestation verify oci://ghcr.io/kogunlowo123/agent-threat-detection:v0.1.0 \
  --owner kogunlowo123
```

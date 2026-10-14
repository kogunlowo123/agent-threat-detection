# Runbook: first deployment and startup

## Prerequisites

- Kubernetes 1.27 or later with workload identity (EKS IRSA, AKS Workload
  Identity or GKE Workload Identity), the External Secrets Operator and a
  `ClusterSecretStore` named `platform-secrets` bound to the cloud secret manager.
- The [agent identity fabric](https://github.com/kogunlowo123/agent-identity-fabric)
  deployed and reachable from the `agent-security` namespace.
- An enterprise IdP with:
  - an application for SOC analysts exposing roles `threat-analyst`,
    `containment-approver` and `detection-engineer`;
  - a confidential client for the detector that can obtain, through the
    client-credentials grant, a token the fabric accepts as an administrator
    token with role `agent-security-officer`.
- Fabric agent registrations for the telemetry collectors (scope
  `telemetry:write`) and for any SOC agents that will use MCP or A2A
  (`threat:read`, `containment:request`).

## 1. Provision cloud resources

```bash
cd deployments/terraform/aws        # or azure / gcp
terraform init                      # configure an encrypted remote backend first
terraform apply -var-file="$ENVIRONMENT.tfvars"
```

Record the outputs: workload-identity role or client id, database secret
name, KMS key, WORM bucket, and the secret containers for the fabric client
secret and the SIEM token.

## 2. Write the secrets Terraform does not hold

```bash
# Audit signing key (Ed25519). Keep the public key for chain verification.
openssl genpkey -algorithm ed25519 \
  | aws secretsmanager create-secret --name agent-threat-detection-audit-key-2026-10 \
      --kms-key-id "$KMS_KEY_ARN" --secret-string file:///dev/stdin

# Client secret issued by the IdP for the detector's confidential client.
aws secretsmanager put-secret-value --secret-id agent-threat-detection-fabric-client-secret \
  --secret-string file://fabric-client-secret.txt

# Token for the SIEM HTTP collector.
aws secretsmanager put-secret-value --secret-id agent-threat-detection-siem-token \
  --secret-string file://siem-token.txt
```

Azure: `az keyvault secret set --vault-name "$VAULT" --name <secret> --file <file>`.
GCP: `gcloud secrets versions add <secret> --data-file=<file>`.
Shred the local files afterwards.

## 3. Namespace and secret sync

```bash
kubectl apply -k deployments/kubernetes
kubectl -n agent-security get externalsecret   # all READY=True
```

## 4. Install the chart

Create `$ENVIRONMENT.yaml` with every value marked REQUIRED in `values.yaml`
plus the workload-identity annotation from Terraform. Start with
`detector.autoContainment: false` (report-only) and list tier-0 agents in
`detector.protectedAgents`.

```bash
helm upgrade --install atd oci://ghcr.io/kogunlowo123/charts/agent-threat-detection \
  --version 0.1.0 -n agent-security -f "$ENVIRONMENT.yaml" --wait
```

## 5. Verify

```bash
kubectl -n agent-security rollout status statefulset/atd-agent-threat-detection
kubectl -n agent-security port-forward svc/atd-agent-threat-detection 8080:80
curl -sf localhost:8080/readyz
curl -s localhost:8080/.well-known/agent-card.json | jq '.skills[].id'
```

Expected: `{"status":"ready"}` and the three skills. Then point a collector
at `POST /v1/traces` (OTLP/HTTP JSON) or `POST /v1/events` and confirm
`atd_events_ingested_total` increases on `/metrics` and the Grafana dashboard
`configs/grafana/agent-threat-detection.json` shows traffic.

## 6. Enable automatic containment

After at least two weeks in report-only mode with alert outcomes reviewed
(see [detection evaluation](../architecture/detection-evaluation.md)), set
`detector.autoContainment: true` and upgrade the release. Record the
decision and the measured false-positive rate in the change ticket.

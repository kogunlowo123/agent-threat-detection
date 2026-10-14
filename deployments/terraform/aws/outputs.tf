output "service_account_role_arn" {
  description = "Annotate the service account with eks.amazonaws.com/role-arn = this value"
  value       = aws_iam_role.detector.arn
}

output "database_url_secret_name" {
  description = "Secrets Manager secret synced to Kubernetes as DATABASE_URL"
  value       = aws_secretsmanager_secret.database_url.name
}

output "kms_key_arn" {
  description = "KMS key that encrypts the database, secrets and audit bucket; use it for audit-key and client secrets"
  value       = aws_kms_key.detector.arn
}

output "audit_bucket" {
  description = "Object Lock (compliance mode) bucket receiving audit chains and OCSF findings"
  value       = aws_s3_bucket.audit.bucket
}

output "fabric_client_secret_name" {
  description = "Secrets Manager secret to populate with the fabric client secret"
  value       = aws_secretsmanager_secret.fabric_client_secret.name
}

output "siem_token_secret_name" {
  description = "Secrets Manager secret to populate with the SIEM collector token"
  value       = aws_secretsmanager_secret.siem_token.name
}

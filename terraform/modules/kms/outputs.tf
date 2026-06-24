output "key_arn" {
  value       = aws_kms_key.audit.arn
  description = "CMK ARN (S3 SSE-KMS에 사용)"
}

output "key_id" {
  value       = aws_kms_key.audit.key_id
  description = "CMK Key ID"
}

output "alias_name" {
  value       = aws_kms_alias.audit.name
  description = "CMK 별칭"
}

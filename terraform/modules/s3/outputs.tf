output "waf_logs_bucket" {
  value = aws_s3_bucket.waf_logs.id
}

output "waf_logs_bucket_arn" {
  value = aws_s3_bucket.waf_logs.arn
}

output "alb_logs_bucket" {
  value = aws_s3_bucket.alb_logs.id
}

output "alb_logs_bucket_arn" {
  value = aws_s3_bucket.alb_logs.arn
}

output "cloudtrail_bucket" {
  value = aws_s3_bucket.cloudtrail_logs.id
}

output "cloudtrail_bucket_arn" {
  value = aws_s3_bucket.cloudtrail_logs.arn
}

output "audit_evidence_bucket" {
  value       = aws_s3_bucket.audit_evidence.id
  description = "ISMS-P 감사 증적 버킷 이름"
}

output "audit_evidence_bucket_arn" {
  value       = aws_s3_bucket.audit_evidence.arn
  description = "ISMS-P 감사 증적 버킷 ARN"
}
output "alb_dns_name" {
  value       = module.alb.alb_dns_name
  description = "ALB DNS 주소 (브라우저에서 접속)"
}

output "app_public_ip" {
  value       = module.ec2.app_public_ip
  description = "앱 서버 퍼블릭 IP"
}

output "analysis_public_ip" {
  value       = module.ec2.analysis_public_ip
  description = "분석 서버 퍼블릭 IP (Grafana)"
}

output "waf_logs_bucket" {
  value       = module.s3.waf_logs_bucket
  description = "WAF 로그 S3 버킷 이름"
}

output "audit_evidence_bucket" {
  value       = module.s3.audit_evidence_bucket
  description = "ISMS-P 감사 증적 버킷 이름 (Object Lock COMPLIANCE)"
}

output "guardduty_detector_id" {
  value       = aws_guardduty_detector.main.id
  description = "GuardDuty 탐지기 ID"
}

# KMS 출력 — 프리티어 종료 후 KMS 모듈 활성화 시 주석 해제
# output "kms_key_id" {
#   value       = module.kms.key_id
#   description = "감사 증적 CMK Key ID"
# }
#
# output "kms_alias" {
#   value       = module.kms.alias_name
#   description = "감사 증적 CMK 별칭"
# }
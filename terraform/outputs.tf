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
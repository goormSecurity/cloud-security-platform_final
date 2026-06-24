# ── AWS Config (ISMS-P 2.10 드리프트 감지) ───────────────────────────────
# 프리티어 종료 후 활성화 — modules/logging/main.tf 주석 해제
# WAF/ALB/S3 타입만 기록하여 과금 최소화 ($0.003/건)
#
# resource "aws_iam_role" "config" { ... }
# resource "aws_config_configuration_recorder" "main" { ... }
# resource "aws_config_delivery_channel" "main" { ... }
# resource "aws_config_configuration_recorder_status" "main" { ... }

# ── CloudTrail ───────────────────────────────────────────────────────────────
resource "aws_cloudtrail" "main" {
  name                          = "${var.project_name}-trail"
  s3_bucket_name                = var.cloudtrail_bucket
  s3_key_prefix                 = "cloudtrail"
  include_global_service_events = true
  is_multi_region_trail         = false
  enable_log_file_validation    = true

  tags = {
    Name = "${var.project_name}-trail"
  }
}
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
data "aws_caller_identity" "current" {}

resource "aws_kms_key" "audit" {
  description             = "CMK for WAF audit evidence bucket (ISMS-P 2.7)"
  deletion_window_in_days = 30
  enable_key_rotation     = true

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "Enable IAM User Permissions"
        Effect = "Allow"
        Principal = { AWS = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root" }
        Action   = "kms:*"
        Resource = "*"
      },
      {
        Sid    = "Allow S3 Service"
        Effect = "Allow"
        Principal = { Service = "s3.amazonaws.com" }
        Action   = ["kms:GenerateDataKey", "kms:Decrypt"]
        Resource = "*"
      },
      {
        Sid    = "Allow Config Service"
        Effect = "Allow"
        Principal = { Service = "config.amazonaws.com" }
        Action   = ["kms:GenerateDataKey", "kms:Decrypt"]
        Resource = "*"
      }
    ]
  })

  tags = {
    Name        = "${var.project_name}-audit-cmk"
    Environment = var.environment
    Purpose     = "ISMS-P 2.7 감사 증적 버킷 암호화"
  }
}

resource "aws_kms_alias" "audit" {
  name          = "alias/${var.project_name}-audit-cmk"
  target_key_id = aws_kms_key.audit.key_id
}

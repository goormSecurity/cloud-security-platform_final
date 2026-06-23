# WAF 로그 버킷 (이름이 반드시 aws-waf-logs- 로 시작해야 함)
resource "aws_s3_bucket" "waf_logs" {
  bucket = "aws-waf-logs-${var.project_name}-${var.environment}"

  tags = {
    Name = "WAF Logs Bucket"
  }
}

resource "aws_s3_bucket_versioning" "waf_logs" {
  bucket = aws_s3_bucket.waf_logs.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_public_access_block" "waf_logs" {
  bucket                  = aws_s3_bucket.waf_logs.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_lifecycle_configuration" "waf_logs" {
  bucket = aws_s3_bucket.waf_logs.id

  rule {
    id     = "delete-old-logs"
    status = "Enabled"

    filter {}

    expiration {
      days = 90
    }
  }
}

# ALB 로그 버킷
resource "aws_s3_bucket" "alb_logs" {
  bucket = "${var.project_name}-alb-logs-${var.environment}"

  tags = {
    Name = "ALB Logs Bucket"
  }
}

resource "aws_s3_bucket_public_access_block" "alb_logs" {
  bucket                  = aws_s3_bucket.alb_logs.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_policy" "alb_logs" {
  bucket = aws_s3_bucket.alb_logs.id
  policy = data.aws_iam_policy_document.alb_logs.json
}

data "aws_iam_policy_document" "alb_logs" {
  statement {
    principals {
      type        = "AWS"
      identifiers = ["arn:aws:iam::600734575887:root"]
    }
    actions   = ["s3:PutObject"]
    resources = ["${aws_s3_bucket.alb_logs.arn}/alb-logs/AWSLogs/*"]
  }
}

# WAF 로그 버킷 — SSE-S3 암호화 (프리티어; CMK 전환 시 aws:kms로 변경)
resource "aws_s3_bucket_server_side_encryption_configuration" "waf_logs" {
  bucket = aws_s3_bucket.waf_logs.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

# Audit Evidence 버킷 — Object Lock COMPLIANCE 모드 (ISMS-P 2.7 무결성)
# Object Lock 은 버킷 생성 시에만 활성화 가능
resource "aws_s3_bucket" "audit_evidence" {
  bucket              = "${var.project_name}-audit-evidence-${var.environment}"
  object_lock_enabled = true

  tags = {
    Name    = "Audit Evidence Bucket"
    Purpose = "ISMS-P audit evidence with Object Lock"
  }
}

resource "aws_s3_bucket_versioning" "audit_evidence" {
  bucket = aws_s3_bucket.audit_evidence.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_public_access_block" "audit_evidence" {
  bucket                  = aws_s3_bucket.audit_evidence.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# audit-evidence 버킷 — SSE-S3 암호화 (프리티어; CMK 전환 시 aws:kms로 변경)
resource "aws_s3_bucket_server_side_encryption_configuration" "audit_evidence" {
  bucket = aws_s3_bucket.audit_evidence.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_object_lock_configuration" "audit_evidence" {
  bucket = aws_s3_bucket.audit_evidence.id

  rule {
    default_retention {
      mode = "COMPLIANCE"
      days = 365
    }
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "audit_evidence" {
  bucket = aws_s3_bucket.audit_evidence.id

  rule {
    id     = "transition-to-ia"
    status = "Enabled"
    filter {}

    transition {
      days          = 90
      storage_class = "STANDARD_IA"
    }
  }
}

# CloudTrail 로그 버킷
resource "aws_s3_bucket" "cloudtrail_logs" {
  bucket = "${var.project_name}-cloudtrail-${var.environment}"

  tags = {
    Name = "CloudTrail Logs Bucket"
  }
}

resource "aws_s3_bucket_public_access_block" "cloudtrail_logs" {
  bucket                  = aws_s3_bucket.cloudtrail_logs.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_policy" "cloudtrail" {
  bucket = aws_s3_bucket.cloudtrail_logs.id
  policy = data.aws_iam_policy_document.cloudtrail.json
}

data "aws_iam_policy_document" "cloudtrail" {
  statement {
    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }
    actions   = ["s3:GetBucketAcl"]
    resources = [aws_s3_bucket.cloudtrail_logs.arn]
  }

  statement {
    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }
    actions   = ["s3:PutObject"]
    resources = ["${aws_s3_bucket.cloudtrail_logs.arn}/cloudtrail/AWSLogs/*"]
    condition {
      test     = "StringEquals"
      variable = "s3:x-amz-acl"
      values   = ["bucket-owner-full-control"]
    }
  }
}
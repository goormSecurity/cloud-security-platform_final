# Terraform S3 백엔드 — 부분 구성 (partial backend configuration)
#
# 배포 방법:
#   1. backend.hcl.example 을 backend.hcl 로 복사 후 수정
#   2. terraform init -backend-config=backend.hcl
#
# 기존 state 이전:
#   terraform init -backend-config=backend.hcl -migrate-state

terraform {
  backend "s3" {}
}

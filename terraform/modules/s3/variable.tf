variable "project_name" {
  type = string
}

variable "environment" {
  type    = string
  default = "dev"
}

# KMS CMK ARN — 프리티어 종료 후 SSE-KMS 전환 시 활성화
# variable "kms_key_arn" {
#   description = "CMK ARN — WAF 로그 버킷 및 audit-evidence 버킷 SSE-KMS 암호화에 사용"
#   type        = string
#   default     = ""
# }
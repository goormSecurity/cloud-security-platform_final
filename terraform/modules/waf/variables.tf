variable "project_name" {
  type = string
}

variable "alb_arn" {
  type = string
}

variable "waf_logs_bucket_arn" {
  type = string
}

variable "blocked_ips" {
  description = "분석 엔진이 HIGH 위험으로 판정한 IP 목록 (CIDR 형식, /32 포함)"
  type        = list(string)
  default     = []
}
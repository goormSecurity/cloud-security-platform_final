variable "aws_region" {
  description = "AWS 리전"
  type        = string
  default     = "ap-northeast-2"
}

variable "environment" {
  description = "환경 구분"
  type        = string
  default     = "dev"
}

variable "project_name" {
  description = "프로젝트명"
  type        = string
  default     = "cloud-sec"
}

variable "vpc_cidr" {
  description = "VPC CIDR"
  type        = string
  default     = "10.0.0.0/16"
}

variable "ssh_public_key" {
  description = "SSH 퍼블릭 키"
  type        = string
}
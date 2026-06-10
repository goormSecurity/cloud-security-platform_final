variable "project_name" {
  type = string
}

variable "vpc_id" {
  type = string
}

variable "public_subnet_ids" {
  type = list(string)
}

variable "private_subnet_ids" {
  type = list(string)
}

variable "app_sg_id" {
  type = string
}

variable "instance_type_app" {
  type    = string
  default = "t3.small"
}

variable "instance_type_analysis" {
  type    = string
  default = "t3.small"
}

variable "ssh_public_key" {
  type = string
}
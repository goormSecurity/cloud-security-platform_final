terraform {
  backend "s3" {
    bucket         = "cloudsecurity-6-677673473281-ap-northeast-2-an"
    key            = "cloud-security/terraform.tfstate"
    region         = "ap-northeast-2"
    use_lockfile   = true
    encrypt        = true
  }
}
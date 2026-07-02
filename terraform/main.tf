module "networking" {
  source       = "./modules/networking"
  project_name = var.project_name
  vpc_cidr     = var.vpc_cidr
}

# KMS CMK 모듈 — 프리티어 종료 후 활성화 (modules/kms/ 코드 준비됨)
# module "kms" {
#   source       = "./modules/kms"
#   project_name = var.project_name
#   environment  = var.environment
# }

module "s3" {
  source       = "./modules/s3"
  project_name = var.project_name
  environment  = var.environment
}

module "ec2" {
  source                 = "./modules/ec2"
  project_name           = var.project_name
  vpc_id                 = module.networking.vpc_id
  public_subnet_ids      = module.networking.public_subnet_ids
  private_subnet_ids     = module.networking.private_subnet_ids
  app_sg_id              = module.networking.app_sg_id
  instance_type_app      = "t3.small"
  instance_type_analysis = "t3.xlarge"
  ssh_public_key         = var.ssh_public_key
}

module "alb" {
  source            = "./modules/alb"
  project_name      = var.project_name
  vpc_id            = module.networking.vpc_id
  public_subnet_ids = module.networking.public_subnet_ids
  alb_sg_id         = module.networking.alb_sg_id
  alb_logs_bucket   = module.s3.alb_logs_bucket
  app_instance_id   = module.ec2.app_instance_id
}

module "waf" {
  source              = "./modules/waf"
  project_name        = var.project_name
  alb_arn             = module.alb.alb_arn
  waf_logs_bucket_arn = module.s3.waf_logs_bucket_arn
  blocked_ips         = var.blocked_ips
}

module "logging" {
  source            = "./modules/logging"
  project_name      = var.project_name
  cloudtrail_bucket = module.s3.cloudtrail_bucket
  depends_on        = [module.s3]
}

resource "aws_guardduty_detector" "main" {
  enable = true

  datasources {
    s3_logs {
      enable = true
    }
    malware_protection {
      scan_ec2_instance_with_findings {
        ebs_volumes {
          enable = true
        }
      }
    }
  }

  tags = {
    Project     = var.project_name
    Environment = var.environment
  }
}
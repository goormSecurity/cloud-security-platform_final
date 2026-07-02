# 키페어
resource "aws_key_pair" "main" {
  key_name   = "${var.project_name}-key"
  public_key = var.ssh_public_key
}

# Amazon Linux 2023 AMI
data "aws_ami" "amazon_linux" {
  most_recent = true
  owners      = ["amazon"]

  filter {
    name   = "name"
    values = ["al2023-ami-*-x86_64"]
  }
}

# 앱 서버 (DVWA + Juice Shop)
resource "aws_instance" "app" {
  ami                    = data.aws_ami.amazon_linux.id
  instance_type          = var.instance_type_app
  key_name               = aws_key_pair.main.key_name
  vpc_security_group_ids = [var.app_sg_id]
  subnet_id              = var.public_subnet_ids[0]
  iam_instance_profile   = aws_iam_instance_profile.app.name

  lifecycle {
    ignore_changes = [ami, user_data]
  }

  user_data = base64encode(<<-EOF
    #!/bin/bash
    yum update -y
    yum install -y docker
    systemctl start docker
    systemctl enable docker
    usermod -aG docker ec2-user

    curl -L "https://github.com/docker/compose/releases/latest/download/docker-compose-$(uname -s)-$(uname -m)" \
      -o /usr/local/bin/docker-compose
    chmod +x /usr/local/bin/docker-compose

    docker run -d \
      --name dvwa \
      --restart always \
      -p 80:80 \
      vulnerables/web-dvwa

    docker run -d \
      --name juiceshop \
      --restart always \
      -p 3000:3000 \
      bkimminich/juice-shop
  EOF
  )

  root_block_device {
    volume_size = 30
    volume_type = "gp3"
  }

  tags = {
    Name = "${var.project_name}-app-server"
    Role = "app"
  }
}

# 분석 서버 (Grafana + Loki)
resource "aws_instance" "analysis" {
  ami                         = data.aws_ami.amazon_linux.id
  instance_type               = var.instance_type_analysis
  key_name                    = aws_key_pair.main.key_name
  vpc_security_group_ids      = [aws_security_group.analysis.id]
  subnet_id                   = var.public_subnet_ids[0]
  iam_instance_profile        = aws_iam_instance_profile.analysis.name
  user_data_replace_on_change = true

  lifecycle {
    ignore_changes = [ami, user_data, root_block_device]
  }

  user_data = base64encode(file("${path.module}/templates/analysis_setup.sh"))

  root_block_device {
    volume_size = 30
    volume_type = "gp3"
  }

  tags = {
    Name = "${var.project_name}-analysis-server"
    Role = "analysis"
  }
}

# IAM 역할 - 앱 서버
resource "aws_iam_role" "app" {
  name = "${var.project_name}-app-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
    }]
  })
}

resource "aws_iam_instance_profile" "app" {
  name = "${var.project_name}-app-profile"
  role = aws_iam_role.app.name
}

# IAM 역할 - 분석 서버
resource "aws_iam_role" "analysis" {
  name = "${var.project_name}-analysis-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
    }]
  })
}

resource "aws_iam_role_policy" "analysis_s3" {
  name = "s3-log-read"
  role = aws_iam_role.analysis.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = ["s3:GetObject", "s3:ListBucket"]
        Resource = [
          "arn:aws:s3:::aws-waf-logs-*",
          "arn:aws:s3:::aws-waf-logs-*/*",
          "arn:aws:s3:::${var.project_name}-*",
          "arn:aws:s3:::${var.project_name}-*/*"
        ]
      },
      {
        Effect = "Allow"
        Action = ["s3:PutObject", "s3:PutObjectAcl", "s3:ListAllMyBuckets"]
        Resource = [
          "arn:aws:s3:::${var.project_name}-audit-evidence-*",
          "arn:aws:s3:::${var.project_name}-audit-evidence-*/*",
          "arn:aws:s3:::*"
        ]
      },
      {
        Effect   = "Allow"
        Action   = ["wafv2:GetWebACL", "wafv2:ListWebACLs", "wafv2:GetLoggingConfiguration",
                    "wafv2:ListIPSets", "wafv2:GetIPSet", "wafv2:UpdateIPSet"]
        Resource = "*"
      },
      {
        Effect   = "Allow"
        Action   = ["ssm:GetParameter", "ssm:GetParameters", "ssm:GetParametersByPath"]
        Resource = "arn:aws:ssm:ap-northeast-2:*:parameter/cloud-sec/*"
      },
      {
        Effect   = "Allow"
        Action   = ["cloudtrail:LookupEvents", "cloudtrail:DescribeTrails", "cloudtrail:GetTrail",
                    "cloudtrail:GetTrailStatus"]
        Resource = "*"
      },
      {
        Effect   = "Allow"
        Action   = ["iam:ListUsers", "iam:ListRoles", "iam:ListPolicies",
                    "iam:GetAccountPasswordPolicy", "iam:GenerateCredentialReport",
                    "iam:GetCredentialReport", "iam:ListAccessKeys", "iam:ListMFADevices",
                    "iam:ListAttachedRolePolicies", "iam:ListRolePolicies"]
        Resource = "*"
      }
    ]
  })
}

resource "aws_iam_instance_profile" "analysis" {
  name = "${var.project_name}-analysis-profile"
  role = aws_iam_role.analysis.name
}

# 분석 서버 Elastic IP (재시작 후에도 IP 고정)
resource "aws_eip" "analysis" {
  instance = aws_instance.analysis.id
  domain   = "vpc"

  tags = {
    Name = "${var.project_name}-analysis-eip"
  }
}

# 분석 서버 보안그룹
resource "aws_security_group" "analysis" {
  name        = "${var.project_name}-analysis-sg"
  description = "Analysis Server Security Group"
  vpc_id      = var.vpc_id

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    from_port   = 3000
    to_port     = 3000
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    from_port   = 3100
    to_port     = 3100
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    description = "Ollama LLM API"
    from_port   = 11434
    to_port     = 11434
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "${var.project_name}-analysis-sg"
  }
}
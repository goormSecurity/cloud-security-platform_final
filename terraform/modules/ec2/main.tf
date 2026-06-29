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
    volume_size = 20
    volume_type = "gp3"
  }

  tags = {
    Name = "${var.project_name}-app-server"
    Role = "app"
  }
}

# 분석 서버 (Grafana + Loki)
resource "aws_instance" "analysis" {
  ami                    = data.aws_ami.amazon_linux.id
  instance_type          = var.instance_type_analysis
  key_name               = aws_key_pair.main.key_name
  vpc_security_group_ids = [aws_security_group.analysis.id]
  subnet_id              = var.public_subnet_ids[0]
  iam_instance_profile   = aws_iam_instance_profile.analysis.name

  user_data = base64encode(<<-EOF
    #!/bin/bash
    exec >> /var/log/user-data.log 2>&1
    set -x

    # 1. 패키지
    yum update -y
    yum install -y docker python3 python3-pip git

    # 2. Docker
    systemctl start docker
    systemctl enable docker
    usermod -aG docker ec2-user
    curl -SL "https://github.com/docker/compose/releases/latest/download/docker-compose-$(uname -s)-$(uname -m)" \
      -o /usr/local/bin/docker-compose
    chmod +x /usr/local/bin/docker-compose

    # 3. 리포지토리 클론
    git clone https://github.com/goormSecurity/cloud-security-platform.git /opt/cloud-security-platform

    # 4. Python 의존성
    pip3 install -r /opt/cloud-security-platform/requirements.txt
    python3 -m playwright install-deps chromium 2>/dev/null || true
    python3 -m playwright install chromium 2>/dev/null || true

    # 5. Ollama 설치 + 모델 다운로드 (llama3.1:8b — 약 4.7GB)
    curl -fsSL https://ollama.com/install.sh | sh
    systemctl enable ollama
    systemctl start ollama
    sleep 60
    ollama pull llama3.1:8b

    # 6. SSM에서 시크릿 가져와 .env 생성
    SSM_GITHUB=$(aws ssm get-parameter --name /cloud-sec/github_token \
      --with-decryption --query Parameter.Value --output text --region ap-northeast-2 2>/dev/null || echo "")
    SSM_ABUSE=$(aws ssm get-parameter --name /cloud-sec/abuseipdb_api_key \
      --with-decryption --query Parameter.Value --output text --region ap-northeast-2 2>/dev/null || echo "")
    SSM_SLACK=$(aws ssm get-parameter --name /cloud-sec/slack_webhook_url \
      --with-decryption --query Parameter.Value --output text --region ap-northeast-2 2>/dev/null || echo "")

    printf 'AWS_DEFAULT_REGION=ap-northeast-2\nGITHUB_TOKEN=%s\nABUSEIPDB_API_KEY=%s\nSLACK_WEBHOOK_URL=%s\n' \
      "$SSM_GITHUB" "$SSM_ABUSE" "$SSM_SLACK" > /opt/cloud-security-platform/.env
    chmod 600 /opt/cloud-security-platform/.env

    # 7. Grafana + Loki (docker-compose)
    mkdir -p /opt/monitoring
    cat > /opt/monitoring/docker-compose.yml << 'COMPOSE'
version: '3'
services:
  loki:
    image: grafana/loki:2.9.0
    ports:
      - "3100:3100"
    restart: always
  grafana:
    image: grafana/grafana:10.2.0
    ports:
      - "3000:3000"
    environment:
      - GF_SECURITY_ADMIN_USER=admin
      - GF_SECURITY_ADMIN_PASSWORD=admin123!
    volumes:
      - grafana-data:/var/lib/grafana
    depends_on:
      - loki
    restart: always
volumes:
  grafana-data:
COMPOSE
    cd /opt/monitoring && docker-compose up -d

    # 8. cron 등록 — 매일 오전 9시 KST (0시 UTC)
    echo "0 0 * * * ec2-user cd /opt/cloud-security-platform && python3 scripts/run_pipeline.py >> /var/log/pipeline.log 2>&1" >> /etc/crontab
  EOF
  )

  root_block_device {
    volume_size = 20
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
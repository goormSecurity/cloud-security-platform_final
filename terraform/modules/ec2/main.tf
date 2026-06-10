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
    yum update -y
    yum install -y docker python3 python3-pip git
    systemctl start docker
    systemctl enable docker
    usermod -aG docker ec2-user

    curl -L "https://github.com/docker/compose/releases/latest/download/docker-compose-$(uname -s)-$(uname -m)" \
      -o /usr/local/bin/docker-compose
    chmod +x /usr/local/bin/docker-compose

    mkdir -p /opt/monitoring
    cat > /opt/monitoring/docker-compose.yml << 'COMPOSE'
version: '3'
services:
  loki:
    image: grafana/loki:latest
    ports:
      - "3100:3100"
    restart: always
  grafana:
    image: grafana/grafana:latest
    ports:
      - "3000:3000"
    environment:
      - GF_SECURITY_ADMIN_PASSWORD=admin123!
    depends_on:
      - loki
    restart: always
COMPOSE

    cd /opt/monitoring && docker-compose up -d
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
        Action   = ["wafv2:UpdateIPSet", "wafv2:GetIPSet"]
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
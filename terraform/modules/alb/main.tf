resource "aws_lb" "main" {
  name               = "${var.project_name}-alb"
  internal           = false
  load_balancer_type = "application"
  security_groups    = [var.alb_sg_id]
  subnets            = var.public_subnet_ids

  access_logs {
    bucket  = var.alb_logs_bucket
    prefix  = "alb-logs"
    enabled = true
  }

  tags = {
    Name = "${var.project_name}-alb"
  }
}

# ── 타겟 그룹 ────────────────────────────────────────────────────

resource "aws_lb_target_group" "dvwa" {
  name     = "${var.project_name}-dvwa-tg"
  port     = 80
  protocol = "HTTP"
  vpc_id   = var.vpc_id

  health_check {
    enabled             = true
    healthy_threshold   = 2
    interval            = 30
    matcher             = "200,302"
    path                = "/"
    timeout             = 5
    unhealthy_threshold = 2
  }
}

resource "aws_lb_target_group" "juiceshop" {
  name     = "${var.project_name}-juice-tg"
  port     = 3000
  protocol = "HTTP"
  vpc_id   = var.vpc_id

  health_check {
    enabled             = true
    path                = "/"
    matcher             = "200"
    interval            = 30
    timeout             = 5
    healthy_threshold   = 2
    unhealthy_threshold = 2
  }
}

resource "aws_lb_target_group" "ghost" {
  name     = "${var.project_name}-ghost-tg"
  port     = 2368
  protocol = "HTTP"
  vpc_id   = var.vpc_id

  health_check {
    enabled             = true
    path                = "/"
    matcher             = "200,301,302"
    interval            = 30
    timeout             = 5
    healthy_threshold   = 2
    unhealthy_threshold = 3
  }
}

# ── 리스너 (기본: DVWA) ──────────────────────────────────────────

resource "aws_lb_listener" "http" {
  load_balancer_arn = aws_lb.main.arn
  port              = "80"
  protocol          = "HTTP"

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.dvwa.arn
  }
}

# ── 경로 기반 라우팅 룰 ──────────────────────────────────────────
# 우선순위: 낮은 숫자 = 먼저 평가

# Ghost CMS: /ghost/*, /rss/, /members/*, /tag/*, /sitemap.xml
resource "aws_lb_listener_rule" "ghost" {
  listener_arn = aws_lb_listener.http.arn
  priority     = 90

  action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.ghost.arn
  }

  condition {
    path_pattern {
      values = [
        "/ghost/*",
        "/rss/",
        "/members/*",
        "/tag/*",
        "/sitemap.xml",
      ]
    }
  }
}

# JuiceShop: /rest/*, /api/*, /socket.io/*
resource "aws_lb_listener_rule" "juiceshop" {
  listener_arn = aws_lb_listener.http.arn
  priority     = 100

  action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.juiceshop.arn
  }

  condition {
    path_pattern {
      values = [
        "/rest/*",
        "/api/*",
        "/socket.io/*",
        "/assets/*",
      ]
    }
  }
}

# ── 타겟 그룹 → EC2 연결 ────────────────────────────────────────

resource "aws_lb_target_group_attachment" "dvwa" {
  target_group_arn = aws_lb_target_group.dvwa.arn
  target_id        = var.app_instance_id
  port             = 80
}

resource "aws_lb_target_group_attachment" "juiceshop" {
  target_group_arn = aws_lb_target_group.juiceshop.arn
  target_id        = var.app_instance_id
  port             = 3000
}

resource "aws_lb_target_group_attachment" "ghost" {
  target_group_arn = aws_lb_target_group.ghost.arn
  target_id        = var.app_instance_id
  port             = 2368
}

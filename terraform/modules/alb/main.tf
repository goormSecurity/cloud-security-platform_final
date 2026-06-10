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

resource "aws_lb_listener" "http" {
  load_balancer_arn = aws_lb.main.arn
  port              = "80"
  protocol          = "HTTP"

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.dvwa.arn
  }
}

resource "aws_lb_listener_rule" "juiceshop" {
  listener_arn = aws_lb_listener.http.arn
  priority     = 100

  action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.juiceshop.arn
  }

  condition {
    path_pattern {
      values = ["/juice/*"]
    }
  }
}

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
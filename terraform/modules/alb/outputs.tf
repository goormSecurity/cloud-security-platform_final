output "alb_dns_name" {
  value = aws_lb.main.dns_name
}

output "alb_arn" {
  value = aws_lb.main.arn
}

output "dvwa_target_group_arn" {
  value = aws_lb_target_group.dvwa.arn
}

output "juiceshop_target_group_arn" {
  value = aws_lb_target_group.juiceshop.arn
}
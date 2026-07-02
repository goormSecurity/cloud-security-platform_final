output "app_instance_id" {
  value = aws_instance.app.id
}

output "app_public_ip" {
  value = aws_instance.app.public_ip
}

output "analysis_instance_id" {
  value = aws_instance.analysis.id
}

output "analysis_public_ip" {
  value = aws_eip.analysis.public_ip
}

output "analysis_sg_id" {
  value = aws_security_group.analysis.id
}
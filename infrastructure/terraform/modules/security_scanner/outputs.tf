# Instance outputs
output "instance_id" {
  description = "ID of the Security Scanner EC2 instance"
  value       = aws_instance.security_scanner.id
}

output "instance_direct_public_ip" {
  description = "Direct public IP address of the security scanner instance"
  value       = aws_instance.security_scanner.public_ip
}

output "instance_elastic_ip" {
  description = "Elastic IP address of the security scanner instance"
  value       = aws_eip.security_scanner.public_ip
}

# Networking outputs
output "vpc_id" {
  description = "ID of the VPC"
  value       = var.vpc_id
}

output "subnet_id" {
  description = "ID of the subnet"
  value       = var.subnet_id
}

output "security_group_id" {
  description = "ID of the Security Scanner security group"
  value       = aws_security_group.security_scanner.id
}

# IAM outputs
output "iam_role_id" {
  description = "ID of the Security Scanner IAM role"
  value       = aws_iam_role.security_scanner.id
}

output "iam_role_arn" {
  description = "ARN of the Security Scanner IAM role"
  value       = aws_iam_role.security_scanner.arn
} 
output "vpc_id" {
  description = "VPC ID."
  value       = aws_vpc.main.id
}

output "public_subnet_ids" {
  description = "List of public subnet IDs."
  value       = [for subnet in aws_subnet.public : subnet.id]
}

output "private_subnet_ids" {
  description = "List of private subnet IDs."
  value       = [for subnet in aws_subnet.private : subnet.id]
}

output "vpc_endpoint_sg_id" {
  description = "Security group ID for VPC endpoints."
  value       = aws_security_group.vpc_endpoints.id
}

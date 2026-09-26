output "asg_name" {
  description = "Compute host Auto Scaling Group name."
  value       = aws_autoscaling_group.compute.name
}

output "security_group_id" {
  description = "Security group ID for compute host instances."
  value       = aws_security_group.compute.id
}

output "ec2_role_arn" {
  description = "ARN of the compute host EC2 IAM role."
  value       = aws_iam_role.compute.arn
}

output "ec2_role_name" {
  description = "Name of the compute host EC2 IAM role."
  value       = aws_iam_role.compute.name
}

output "ssm_start_session_command" {
  description = "AWS CLI command for SSM shell session on any compute instance."
  value       = "aws ssm start-session --region ${data.aws_region.current.region} --target <instance-id>"
}

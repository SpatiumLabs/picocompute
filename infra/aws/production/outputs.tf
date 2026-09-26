output "vpc_id" {
  description = "Production VPC ID."
  value       = module.vpc.vpc_id
}

output "eks_cluster_name" {
  description = "EKS cluster name."
  value       = module.eks.cluster_name
}

output "eks_cluster_endpoint" {
  description = "EKS cluster API server endpoint."
  value       = module.eks.cluster_endpoint
}

output "ecr_repository_url" {
  description = "ECR repository URL for the API container image."
  value       = module.eks.ecr_repository_url
}

output "artifact_bucket" {
  description = "S3 bucket for guest image artifacts (rootfs, kernel, guest-agent)."
  value       = aws_s3_bucket.artifacts.id
}

output "snapshot_bucket" {
  description = "S3 bucket for encrypted snapshot blobs and lineage metadata."
  value       = aws_s3_bucket.snapshots.id
}

output "artifact_kms_key_arn" {
  description = "KMS key ARN for the artifact bucket."
  value       = aws_kms_key.artifacts.arn
}

output "snapshot_kms_key_arn" {
  description = "KMS key ARN for the snapshot bucket."
  value       = aws_kms_key.snapshots.arn
}

output "compute_role_arn" {
  description = "Compute host IAM role ARN."
  value       = module.compute_host.ec2_role_arn
}

output "compute_asg_name" {
  description = "Compute host Auto Scaling Group name."
  value       = module.compute_host.asg_name
}

output "compute_security_group_id" {
  description = "Compute host security group ID."
  value       = module.compute_host.security_group_id
}

output "db_endpoint" {
  description = "Aurora cluster writer endpoint."
  value       = aws_rds_cluster.main.endpoint
}

output "db_port" {
  description = "Aurora cluster port."
  value       = aws_rds_cluster.main.port
}

output "db_cluster_identifier" {
  description = "Aurora cluster identifier."
  value       = aws_rds_cluster.main.cluster_identifier
}

output "db_secret_arn" {
  description = "ARN of the Secrets Manager secret containing database credentials."
  value       = aws_rds_cluster.main.master_user_secret[0].secret_arn
}

output "db_security_group_id" {
  description = "Database security group ID."
  value       = aws_security_group.database.id
}

output "dashboard_name" {
  description = "CloudWatch ops dashboard name."
  value       = try(aws_cloudwatch_dashboard.main[0].dashboard_name, null)
}

output "guardduty_detector_id" {
  description = "GuardDuty detector ID."
  value       = try(aws_guardduty_detector.main[0].id, null)
}

output "cloudtrail_arn" {
  description = "CloudTrail ARN."
  value       = try(aws_cloudtrail.main[0].arn, null)
}

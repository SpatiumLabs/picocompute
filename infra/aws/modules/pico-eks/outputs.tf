output "cluster_name" {
  description = "EKS cluster name."
  value       = aws_eks_cluster.main.name
}

output "cluster_endpoint" {
  description = "EKS cluster API server endpoint."
  value       = aws_eks_cluster.main.endpoint
}

output "cluster_certificate_authority_data" {
  description = "Base64-encoded certificate authority data for the EKS cluster."
  value       = aws_eks_cluster.main.certificate_authority[0].data
}

output "oidc_provider_arn" {
  description = "ARN of the OIDC provider for IRSA."
  value       = aws_iam_openid_connect_provider.main.arn
}

output "oidc_provider_url" {
  description = "URL of the OIDC provider for IRSA."
  value       = aws_iam_openid_connect_provider.main.url
}

output "ecr_repository_url" {
  description = "ECR repository URL for the API container image."
  value       = aws_ecr_repository.api.repository_url
}

output "fargate_role_arn" {
  description = "ARN of the Fargate pod execution role."
  value       = aws_iam_role.fargate.arn
}

output "cluster_security_group_id" {
  description = "Security group ID attached to the EKS cluster."
  value       = aws_eks_cluster.main.vpc_config[0].cluster_security_group_id
}

output "kms_key_arn" {
  description = "ARN of the KMS key used for EKS secret encryption."
  value       = aws_kms_key.eks.arn
}

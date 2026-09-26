variable "project_name" {
  description = "Resource naming prefix."
  type        = string
  default     = "picocompute"
}

variable "environment" {
  description = "Environment tag applied to all resources."
  type        = string
}

variable "vpc_id" {
  description = "VPC ID where resources are deployed."
  type        = string
}

variable "private_subnet_ids" {
  description = "List of private subnet IDs for EKS cluster and Fargate profiles."
  type        = list(string)
}

variable "kubernetes_version" {
  description = "EKS Kubernetes version."
  type        = string
  default     = "1.32"
}

variable "common_tags" {
  description = "Tags applied to all taggable resources."
  type        = map(string)
  default     = {}
}

variable "fargate_namespaces" {
  description = "Kubernetes namespaces for the Fargate profile."
  type        = list(string)
  default     = ["api"]
}

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
  description = "Private subnet IDs for compute host instances."
  type        = list(string)
}

variable "instance_type" {
  description = "EC2 instance type for compute hosts."
  type        = string
  default     = "m7i.4xlarge"
}

variable "use_spot" {
  description = "Use spot instances."
  type        = bool
  default     = true
}

variable "ebs_volume_size" {
  description = "Root EBS volume size in GiB."
  type        = number
  default     = 50
}

variable "asg_min_size" {
  description = "ASG minimum size."
  type        = number
  default     = 1
}

variable "asg_max_size" {
  description = "ASG maximum size."
  type        = number
  default     = 10
}

variable "asg_desired_size" {
  description = "ASG desired capacity."
  type        = number
  default     = 1
}

variable "cpu_target_tracking_value" {
  description = "Target CPU utilization percentage for autoscaling."
  type        = number
  default     = 70
}

variable "key_pair_name" {
  description = "Optional EC2 key pair name."
  type        = string
  default     = null
}

variable "ssh_allowed_cidrs" {
  description = "CIDR blocks allowed to reach SSH."
  type        = list(string)
  default     = []
}

variable "enable_ssm" {
  description = "Attach SSM Session Manager policy to EC2 role."
  type        = bool
  default     = true
}

variable "commit" {
  description = "Git commit SHA of the picocompute repo used to locate pre-built binaries in the asset cache."
  type        = string
}

variable "asset_cache_bucket" {
  description = "S3 bucket name for VM asset cache."
  type        = string
  default     = ""
}

variable "asset_cache_prefix" {
  description = "S3 key prefix for VM asset cache."
  type        = string
  default     = "assets"
}

variable "idle_timeout_secs" {
  description = "Default sandbox idle timeout in seconds."
  type        = number
  default     = 3600
}

variable "domain_name" {
  description = "FQDN for the PicoCompute API."
  type        = string
  default     = ""
}

variable "runtime" {
  description = "Sandbox runtime backend (firecracker or qemu)."
  type        = string
  default     = "firecracker"

  validation {
    condition     = contains(["firecracker", "qemu"], var.runtime)
    error_message = "runtime must be firecracker or qemu."
  }
}

variable "additional_kms_key_arns" {
  description = "KMS key ARNs for EC2 role access (decrypt, generate data key)."
  type        = list(string)
  default     = []
}

variable "control_plane_security_group_id" {
  description = "Security group ID of the control plane (EKS cluster SG)."
  type        = string
}

variable "alarm_sns_topic_arn" {
  description = "ARN of the SNS topic for CloudWatch alarm notifications."
  type        = string
  default     = ""
}

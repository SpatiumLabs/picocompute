variable "aws_region" {
  description = "AWS region."
  type        = string
  default     = "us-east-1"
}

variable "vpc_cidr" {
  description = "CIDR block for the production VPC."
  type        = string
  default     = "10.1.0.0/16"
}

# --- Module inputs ---

variable "project_name" {
  description = "Resource naming prefix."
  type        = string
  default     = "picocompute"
}

variable "environment" {
  description = "Environment tag."
  type        = string
  default     = "staging"
}

variable "instance_type" {
  description = "EC2 instance type for compute hosts."
  type        = string
}

variable "commit" {
  description = "Git commit SHA for locating pre-built binaries in the asset cache."
  type        = string
}

variable "runtime" {
  description = "Sandbox runtime backend (firecracker or qemu)."
  type        = string
  default     = "firecracker"
}

variable "api_desired_count" {
  description = "Number of EKS Fargate tasks for the API."
  type        = number
  default     = 1
}

variable "use_spot" {
  description = "Use spot instances."
  type        = bool
}

variable "ebs_volume_size" {
  description = "Root EBS volume size in GiB."
  type        = number
}

variable "asg_min_size" {
  description = "ASG minimum size."
  type        = number
}

variable "asg_max_size" {
  description = "ASG maximum size."
  type        = number
}

variable "asg_desired_size" {
  description = "ASG desired capacity."
  type        = number
}

variable "cpu_target_tracking_value" {
  description = "Target CPU utilization for autoscaling."
  type        = number
}

variable "domain_name" {
  description = "FQDN for the PicoCompute API."
  type        = string
}

variable "cloudflare_zone_id" {
  description = "Cloudflare zone ID."
  type        = string
}

variable "cloudflare_proxy_api" {
  description = "Proxy API DNS through Cloudflare."
  type        = bool
}

variable "alerts_email" {
  description = "Email address for CloudWatch alarm notifications. Leave empty to skip SNS subscription."
  type        = string
  default     = ""
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
  description = "Attach SSM policy to EC2 role."
  type        = bool
  default     = true
}

variable "pico_api_token_parameter_name" {
  description = "SSM parameter for PicoCompute API token."
  type        = string
}

variable "asset_cache_prefix" {
  description = "S3 key prefix for asset cache."
  type        = string
  default     = "assets"
}

variable "idle_timeout_secs" {
  description = "Default sandbox idle timeout in seconds."
  type        = number
  default     = 3600
}

variable "enable_detective_controls" {
  description = "Enable GuardDuty, Security Hub, CloudTrail, and AWS Config."
  type        = bool
  default     = true
}

# --- Database (Aurora PostgreSQL) ---

variable "db_cluster_instance_class" {
  description = "Aurora cluster instance class."
  type        = string
  default     = "db.r6g.large"
}

variable "db_engine_version" {
  description = "Aurora PostgreSQL engine version (major.minor)."
  type        = string
  default     = "18.0"
}

variable "db_cluster_instance_count" {
  description = "Number of instances in the Aurora cluster (2 for HA, 1 for single-AZ)."
  type        = number
  default     = 1
}

variable "db_backup_retention_days" {
  description = "Aurora automated backup retention in days."
  type        = number
  default     = 7
}

variable "db_auto_minor_version_upgrade" {
  description = "Enable automatic minor version upgrades for Aurora instances."
  type        = bool
  default     = true
}

variable "db_deletion_protection" {
  description = "Enable deletion protection for the Aurora cluster."
  type        = bool
  default     = false
}

variable "performance_insights_retention_period" {
  description = "Performance Insights retention in days (7 is free, 731 is paid)."
  type        = number
  default     = 7
}

variable "db_monitoring_interval" {
  description = "Enhanced Monitoring interval in seconds (0=disabled, 1, 5, 10, 15, 30, 60)."
  type        = number
  default     = 30
}

# --- Metrics ---

variable "enable_dashboard" {
  description = "Create the CloudWatch ops dashboard."
  type        = bool
  default     = true
}

variable "enable_observability" {
  description = "Deploy kube-prometheus-stack and OTel collector into the staging cluster."
  type        = bool
  default     = true
}

variable "otel_endpoint" {
  description = "OTLP gRPC endpoint for pico-api export. Must include scheme; use http:// for plaintext in-cluster collectors."
  type        = string
  default     = "http://opentelemetry-collector.monitoring.svc.cluster.local:4317"
}

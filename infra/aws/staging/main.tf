provider "aws" {
  region = var.aws_region
}

provider "cloudflare" {}

provider "kubernetes" {
  host                   = module.eks.cluster_endpoint
  cluster_ca_certificate = base64decode(module.eks.cluster_certificate_authority_data)

  exec {
    api_version = "client.authentication.k8s.io/v1beta1"
    args        = ["eks", "get-token", "--cluster-name", module.eks.cluster_name]
    command     = "aws"
  }
}

provider "helm" {
  kubernetes {
    host                   = module.eks.cluster_endpoint
    cluster_ca_certificate = base64decode(module.eks.cluster_certificate_authority_data)

    exec {
      api_version = "client.authentication.k8s.io/v1beta1"
      args        = ["eks", "get-token", "--cluster-name", module.eks.cluster_name]
      command     = "aws"
    }
  }
}

data "aws_availability_zones" "available" {
  state = "available"
}

data "aws_region" "current" {}

data "aws_caller_identity" "current" {}

data "aws_partition" "current" {}

locals {
  name_prefix = "${var.project_name}-${var.environment}"
  common_tags = {
    Project     = var.project_name
    Environment = var.environment
    ManagedBy   = "terraform"
  }
}

# --- SNS Topic for Alarms ---

resource "aws_sns_topic" "alarms" {
  name = "${local.name_prefix}-alarms"
  tags = local.common_tags
}

resource "aws_sns_topic_subscription" "alarms_email" {
  count     = var.alerts_email != "" ? 1 : 0
  topic_arn = aws_sns_topic.alarms.arn
  protocol  = "email"
  endpoint  = var.alerts_email
}

# --- VPC Module ---

module "vpc" {
  source = "../modules/pico-vpc"

  project_name       = var.project_name
  environment        = var.environment
  vpc_cidr           = var.vpc_cidr
  availability_zones = data.aws_availability_zones.available.names
  common_tags        = local.common_tags
}

# --- ALB Access Logs Bucket ---

resource "aws_s3_bucket" "alb_logs" {
  bucket        = "${local.name_prefix}-alb-logs"
  force_destroy = true

  tags = merge(local.common_tags, {
    Name = "${local.name_prefix}-alb-logs"
  })
}

resource "aws_s3_bucket_server_side_encryption_configuration" "alb_logs" {
  bucket = aws_s3_bucket.alb_logs.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_public_access_block" "alb_logs" {
  bucket                  = aws_s3_bucket.alb_logs.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

data "aws_elb_service_account" "main" {}

resource "aws_s3_bucket_policy" "alb_logs" {
  bucket = aws_s3_bucket.alb_logs.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "AllowELBLogDelivery"
        Effect = "Allow"
        Principal = {
          AWS = data.aws_elb_service_account.main.arn
        }
        Action   = "s3:PutObject"
        Resource = "${aws_s3_bucket.alb_logs.arn}/*"
      },
    ]
  })
}

# --- Backup Plan ---

resource "aws_backup_vault" "main" {
  name        = "${local.name_prefix}-backup-vault"
  kms_key_arn = aws_kms_key.backup.arn

  tags = merge(local.common_tags, {
    Name = "${local.name_prefix}-backup-vault"
  })
}

resource "aws_kms_key" "backup" {
  description             = "KMS key for PicoCompute ${var.environment} backup vault"
  deletion_window_in_days = 30
  enable_key_rotation     = true

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "EnableIAMAdminAccess"
        Effect = "Allow"
        Principal = {
          AWS = "arn:${data.aws_partition.current.partition}:iam::${data.aws_caller_identity.current.account_id}:root"
        }
        Action   = "kms:*"
        Resource = "*"
      },
      {
        Sid    = "AllowBackupService"
        Effect = "Allow"
        Principal = {
          Service = "backup.amazonaws.com"
        }
        Action = [
          "kms:Decrypt",
          "kms:GenerateDataKey",
          "kms:DescribeKey",
        ]
        Resource = "*"
      },
    ]
  })

  tags = merge(local.common_tags, {
    Name = "${local.name_prefix}-backup-key"
  })
}

resource "aws_backup_plan" "main" {
  name = "${local.name_prefix}-backup-plan"

  rule {
    rule_name         = "${local.name_prefix}-daily-backup"
    target_vault_name = aws_backup_vault.main.name
    schedule          = "cron(0 6 * * ? *)"
    start_window      = 60
    completion_window = 120

    lifecycle {
      delete_after = 30
    }

    recovery_point_tags = merge(local.common_tags, {
      Name = "${local.name_prefix}-backup-rp"
    })
  }

  tags = merge(local.common_tags, {
    Name = "${local.name_prefix}-backup-plan"
  })
}

resource "aws_backup_selection" "ebs" {
  name         = "${local.name_prefix}-ebs-backup"
  plan_id      = aws_backup_plan.main.id
  resources    = ["arn:${data.aws_partition.current.partition}:ec2:${data.aws_region.current.region}:${data.aws_caller_identity.current.account_id}:instance/*"]
  iam_role_arn = aws_iam_role.backup.arn

  condition {
    string_equals {
      key   = "aws:ResourceTag/Environment"
      value = var.environment
    }
  }
}

data "aws_iam_policy_document" "backup_assume_role" {
  statement {
    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = ["backup.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "backup" {
  name               = "${local.name_prefix}-backup-role"
  assume_role_policy = data.aws_iam_policy_document.backup_assume_role.json

  tags = merge(local.common_tags, {
    Name = "${local.name_prefix}-backup-role"
  })
}

resource "aws_iam_role_policy_attachment" "backup" {
  role       = aws_iam_role.backup.name
  policy_arn = "arn:${data.aws_partition.current.partition}:iam::aws:policy/service-role/AWSBackupServiceRolePolicyForBackup"
}

# --- SSM Patch Management ---

resource "aws_ssm_patch_baseline" "default" {
  name             = "${local.name_prefix}-patch-baseline"
  description      = "Default patch baseline for PicoCompute ${var.environment}"
  operating_system = "AMAZON_LINUX_2023"

  approval_rule {
    approve_after_days = 7
    compliance_level   = "CRITICAL"

    patch_filter {
      key    = "CLASSIFICATION"
      values = ["Security", "Bugfix"]
    }
  }

  tags = merge(local.common_tags, {
    Name = "${local.name_prefix}-patch-baseline"
  })
}

resource "aws_ssm_maintenance_window" "patch" {
  name                       = "${local.name_prefix}-patch-window"
  schedule                   = "cron(0 9 ? * SUN *)"
  duration                   = 3
  cutoff                     = 1
  allow_unassociated_targets = false

  tags = merge(local.common_tags, {
    Name = "${local.name_prefix}-patch-window"
  })
}

resource "aws_ssm_maintenance_window_target" "patch" {
  window_id     = aws_ssm_maintenance_window.patch.id
  name          = "${local.name_prefix}-patch-target"
  resource_type = "INSTANCE"

  targets {
    key    = "tag:Environment"
    values = [var.environment]
  }
}

resource "aws_ssm_maintenance_window_task" "patch" {
  window_id        = aws_ssm_maintenance_window.patch.id
  task_type        = "RUN_COMMAND"
  task_arn         = "AWS-RunPatchBaseline"
  max_errors       = "1"
  max_concurrency  = "1"
  priority         = 1
  service_role_arn = aws_iam_role.ssm_patch.arn

  targets {
    key    = "WindowTargetIds"
    values = [aws_ssm_maintenance_window_target.patch.id]
  }

  task_invocation_parameters {
    run_command_parameters {
      document_version = "$DEFAULT"

      parameter {
        name   = "Operation"
        values = ["Install"]
      }
    }
  }
}

resource "aws_iam_role" "ssm_patch" {
  name = "${local.name_prefix}-ssm-patch-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          Service = "ssm.amazonaws.com"
        }
        Action = "sts:AssumeRole"
      },
    ]
  })

  tags = merge(local.common_tags, {
    Name = "${local.name_prefix}-ssm-patch-role"
  })
}

resource "aws_iam_role_policy_attachment" "ssm_patch" {
  role       = aws_iam_role.ssm_patch.name
  policy_arn = "arn:${data.aws_partition.current.partition}:iam::aws:policy/AmazonSSMMaintenanceWindowRole"
}

# --- KMS Keys ---

resource "aws_kms_key" "artifacts" {
  description             = "KMS key for PicoCompute ${var.environment} artifact bucket"
  deletion_window_in_days = 30
  enable_key_rotation     = true

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "EnableIAMAdminAccess"
        Effect = "Allow"
        Principal = {
          AWS = "arn:${data.aws_partition.current.partition}:iam::${data.aws_caller_identity.current.account_id}:root"
        }
        Action   = "kms:*"
        Resource = "*"
      },
      {
        Sid    = "AllowEC2RoleUse"
        Effect = "Allow"
        Principal = {
          AWS = module.compute_host.ec2_role_arn
        }
        Action = [
          "kms:Decrypt",
          "kms:GenerateDataKey",
          "kms:DescribeKey",
        ]
        Resource = "*"
      },
      {
        Sid    = "AllowS3Service"
        Effect = "Allow"
        Principal = {
          Service = "s3.amazonaws.com"
        }
        Action = [
          "kms:Decrypt",
          "kms:GenerateDataKey",
        ]
        Resource = "*"
        Condition = {
          StringEquals = {
            "kms:ViaService" = "s3.${data.aws_region.current.region}.amazonaws.com"
          }
        }
      },
    ]
  })

  tags = merge(local.common_tags, {
    Name = "${local.name_prefix}-artifacts-key"
  })
}

resource "aws_kms_key" "snapshots" {
  description             = "KMS key for PicoCompute ${var.environment} snapshot bucket"
  deletion_window_in_days = 30
  enable_key_rotation     = true

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "EnableIAMAdminAccess"
        Effect = "Allow"
        Principal = {
          AWS = "arn:${data.aws_partition.current.partition}:iam::${data.aws_caller_identity.current.account_id}:root"
        }
        Action   = "kms:*"
        Resource = "*"
      },
      {
        Sid    = "AllowEC2RoleUse"
        Effect = "Allow"
        Principal = {
          AWS = module.compute_host.ec2_role_arn
        }
        Action = [
          "kms:Decrypt",
          "kms:GenerateDataKey",
          "kms:DescribeKey",
        ]
        Resource = "*"
      },
      {
        Sid    = "AllowS3Service"
        Effect = "Allow"
        Principal = {
          Service = "s3.amazonaws.com"
        }
        Action = [
          "kms:Decrypt",
          "kms:GenerateDataKey",
        ]
        Resource = "*"
        Condition = {
          StringEquals = {
            "kms:ViaService" = "s3.${data.aws_region.current.region}.amazonaws.com"
          }
        }
      },
    ]
  })

  tags = merge(local.common_tags, {
    Name = "${local.name_prefix}-snapshots-key"
  })
}

# --- Artifact & Snapshot Storage ---

resource "aws_s3_bucket" "artifacts" {
  bucket = "${var.project_name}-${var.environment}-artifacts"

  tags = merge(local.common_tags, {
    Name = "${local.name_prefix}-artifacts"
  })
}

resource "aws_s3_bucket_versioning" "artifacts" {
  bucket = aws_s3_bucket.artifacts.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "artifacts" {
  bucket = aws_s3_bucket.artifacts.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.artifacts.arn
    }
  }
}

resource "aws_s3_bucket_public_access_block" "artifacts" {
  bucket                  = aws_s3_bucket.artifacts.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket" "snapshots" {
  bucket = "${var.project_name}-${var.environment}-snapshots"

  tags = merge(local.common_tags, {
    Name = "${local.name_prefix}-snapshots"
  })
}

resource "aws_s3_bucket_versioning" "snapshots" {
  bucket = aws_s3_bucket.snapshots.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "snapshots" {
  bucket = aws_s3_bucket.snapshots.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.snapshots.arn
    }
  }
}

resource "aws_s3_bucket_public_access_block" "snapshots" {
  bucket                  = aws_s3_bucket.snapshots.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# --- Detective Controls ---

resource "aws_cloudtrail" "main" {
  count = var.enable_detective_controls ? 1 : 0

  name                          = "${local.name_prefix}-trail"
  s3_bucket_name                = aws_s3_bucket.cloudtrail[0].id
  include_global_service_events = true
  is_multi_region_trail         = true
  enable_log_file_validation    = true
  kms_key_id                    = aws_kms_key.cloudtrail[0].arn

  tags = merge(local.common_tags, {
    Name = "${local.name_prefix}-trail"
  })
}

resource "aws_s3_bucket" "cloudtrail" {
  count = var.enable_detective_controls ? 1 : 0

  bucket        = "${local.name_prefix}-cloudtrail"
  force_destroy = true

  tags = merge(local.common_tags, {
    Name = "${local.name_prefix}-cloudtrail"
  })
}

resource "aws_s3_bucket_versioning" "cloudtrail" {
  count  = var.enable_detective_controls ? 1 : 0
  bucket = aws_s3_bucket.cloudtrail[0].id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "cloudtrail" {
  count  = var.enable_detective_controls ? 1 : 0
  bucket = aws_s3_bucket.cloudtrail[0].id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.cloudtrail[0].arn
    }
  }
}

resource "aws_s3_bucket_public_access_block" "cloudtrail" {
  count  = var.enable_detective_controls ? 1 : 0
  bucket = aws_s3_bucket.cloudtrail[0].id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_policy" "cloudtrail" {
  count  = var.enable_detective_controls ? 1 : 0
  bucket = aws_s3_bucket.cloudtrail[0].id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "AWSCloudTrailAclCheck"
        Effect = "Allow"
        Principal = {
          Service = "cloudtrail.amazonaws.com"
        }
        Action   = "s3:GetBucketAcl"
        Resource = aws_s3_bucket.cloudtrail[0].arn
      },
      {
        Sid    = "AWSCloudTrailWrite"
        Effect = "Allow"
        Principal = {
          Service = "cloudtrail.amazonaws.com"
        }
        Action   = "s3:PutObject"
        Resource = "${aws_s3_bucket.cloudtrail[0].arn}/AWSLogs/${data.aws_caller_identity.current.account_id}/*"
        Condition = {
          StringEquals = {
            "s3:x-amz-acl" = "bucket-owner-full-control"
          }
        }
      },
    ]
  })
}

resource "aws_kms_key" "cloudtrail" {
  count = var.enable_detective_controls ? 1 : 0

  description             = "KMS key for PicoCompute ${var.environment} CloudTrail"
  deletion_window_in_days = 30
  enable_key_rotation     = true

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "EnableIAMAdminAccess"
        Effect = "Allow"
        Principal = {
          AWS = "arn:${data.aws_partition.current.partition}:iam::${data.aws_caller_identity.current.account_id}:root"
        }
        Action   = "kms:*"
        Resource = "*"
      },
      {
        Sid    = "AllowCloudTrailEncrypt"
        Effect = "Allow"
        Principal = {
          Service = "cloudtrail.amazonaws.com"
        }
        Action   = "kms:GenerateDataKey"
        Resource = "*"
      },
      {
        Sid    = "AllowCloudTrailDescribe"
        Effect = "Allow"
        Principal = {
          Service = "cloudtrail.amazonaws.com"
        }
        Action   = "kms:DescribeKey"
        Resource = "*"
      },
    ]
  })

  tags = merge(local.common_tags, {
    Name = "${local.name_prefix}-cloudtrail-key"
  })
}

resource "aws_guardduty_detector" "main" {
  count = var.enable_detective_controls ? 1 : 0

  enable                       = true
  finding_publishing_frequency = "FIFTEEN_MINUTES"

  tags = merge(local.common_tags, {
    Name = "${local.name_prefix}-guardduty"
  })
}

resource "aws_securityhub_account" "main" {
  count = var.enable_detective_controls ? 1 : 0

  enable_default_standards = true
}

# --- Database (Aurora PostgreSQL) ---

resource "aws_db_subnet_group" "main" {
  name       = "${local.name_prefix}-db"
  subnet_ids = module.vpc.private_subnet_ids

  tags = merge(local.common_tags, {
    Name = "${local.name_prefix}-db"
  })
}

resource "aws_security_group" "database" {
  name        = "${local.name_prefix}-db-sg"
  description = "Database access for the PicoCompute control plane"
  vpc_id      = module.vpc.vpc_id

  # Ingress rules added after CP module via aws_vpc_security_group_ingress_rule
  # to avoid circular dependency on EKS cluster security group.

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = merge(local.common_tags, {
    Name = "${local.name_prefix}-db-sg"
  })
}

resource "aws_rds_cluster_parameter_group" "main" {
  name        = "${local.name_prefix}-db-pg"
  family      = "aurora-postgresql18"
  description = "Cluster parameter group for PicoCompute ${var.environment} Aurora PostgreSQL 18"

  parameter {
    name  = "log_connections"
    value = "1"
  }

  parameter {
    name  = "log_disconnections"
    value = "1"
  }

  parameter {
    name  = "log_statement"
    value = "ddl"
  }

  tags = merge(local.common_tags, {
    Name = "${local.name_prefix}-db-pg"
  })
}

resource "aws_rds_cluster" "main" {
  cluster_identifier = "${local.name_prefix}-db"

  engine          = "aurora-postgresql"
  engine_version  = var.db_engine_version
  database_name   = "picocompute"
  master_username = "picocompute"

  manage_master_user_password = true

  db_subnet_group_name   = aws_db_subnet_group.main.name
  vpc_security_group_ids = [aws_security_group.database.id]

  db_cluster_parameter_group_name = aws_rds_cluster_parameter_group.main.name

  storage_encrypted = true

  backup_retention_period      = var.db_backup_retention_days
  preferred_backup_window      = "03:00-04:00"
  preferred_maintenance_window = "sun:04:00-sun:05:00"

  deletion_protection = var.db_deletion_protection
  skip_final_snapshot = true

  serverlessv2_scaling_configuration {
    min_capacity = 0.5
    max_capacity = 4
  }

  copy_tags_to_snapshot = true

  enabled_cloudwatch_logs_exports = ["postgresql"]

  tags = merge(local.common_tags, {
    Name = "${local.name_prefix}-db"
  })
}

resource "aws_rds_cluster_instance" "main" {
  count = var.db_cluster_instance_count

  identifier         = "${local.name_prefix}-db-${count.index}"
  cluster_identifier = aws_rds_cluster.main.id
  instance_class     = "db.serverless"
  engine             = aws_rds_cluster.main.engine
  engine_version     = aws_rds_cluster.main.engine_version

  auto_minor_version_upgrade = var.db_auto_minor_version_upgrade

  performance_insights_enabled          = false
  performance_insights_retention_period = var.performance_insights_retention_period
  monitoring_interval                   = var.db_monitoring_interval
  monitoring_role_arn                   = aws_iam_role.rds_enhanced_monitoring.arn

  tags = merge(local.common_tags, {
    Name = "${local.name_prefix}-db-${count.index}"
  })
}

# --- IAM: Enhanced Monitoring for RDS ---

resource "aws_iam_role" "rds_enhanced_monitoring" {
  name        = "${local.name_prefix}-rds-monitor"
  description = "Allows RDS to publish Enhanced Monitoring metrics to CloudWatch Logs"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "monitoring.rds.amazonaws.com"
        }
      }
    ]
  })

  tags = merge(local.common_tags, {
    Name = "${local.name_prefix}-rds-monitor"
  })
}

resource "aws_iam_role_policy_attachment" "rds_enhanced_monitoring" {
  role       = aws_iam_role.rds_enhanced_monitoring.name
  policy_arn = "arn:${data.aws_partition.current.partition}:iam::aws:policy/service-role/AmazonRDSEnhancedMonitoringRole"
}

# --- IRSA: API pods access to DB secret and SSM ---

resource "aws_iam_role" "api_irsa" {
  name = "${local.name_prefix}-api-irsa"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Federated = module.eks.oidc_provider_arn }
      Action    = "sts:AssumeRoleWithWebIdentity"
      Condition = {
        StringEquals = {
          "${replace(module.eks.oidc_provider_url, "https://", "")}:aud" = "sts.amazonaws.com"
          "${replace(module.eks.oidc_provider_url, "https://", "")}:sub" = "system:serviceaccount:api:api"
        }
      }
    }]
  })

  tags = local.common_tags
}

resource "aws_iam_role_policy" "api_irsa" {
  name = "${local.name_prefix}-api-irsa"
  role = aws_iam_role.api_irsa.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = ["secretsmanager:GetSecretValue"]
        Resource = [aws_rds_cluster.main.master_user_secret[0].secret_arn]
      },
      {
        Effect   = "Allow"
        Action   = ["ssm:GetParameter"]
        Resource = ["arn:aws:ssm:${data.aws_region.current.region}:${data.aws_caller_identity.current.account_id}:parameter${var.pico_api_token_parameter_name}"]
      },
    ]
  })
}

# --- CloudWatch Ops Dashboard ---

resource "aws_cloudwatch_dashboard" "main" {
  count = var.enable_dashboard ? 1 : 0

  dashboard_name = "${local.name_prefix}-dashboard"
  dashboard_body = jsonencode({
    widgets = [
      {
        type = "metric"
        properties = {
          view    = "timeSeries"
          stacked = false
          region  = data.aws_region.current.region
          title   = "Compute Hosts CPU"
          period  = 60
          stat    = "Average"
          metrics = [
            ["AWS/AutoScaling", "CPUUtilization", { label = "Compute Hosts", stat = "Average", region = data.aws_region.current.region, dimensions = { AutoScalingGroupName = module.compute_host.asg_name } }],
          ]
          yAxis = {}
        }
      },
      {
        type = "metric"
        properties = {
          view    = "timeSeries"
          stacked = false
          region  = data.aws_region.current.region
          title   = "ASG Instance Count"
          period  = 60
          stat    = "Average"
          metrics = [
            ["AWS/AutoScaling", "GroupInServiceInstances", { label = "Compute Hosts", stat = "Average", region = data.aws_region.current.region, dimensions = { AutoScalingGroupName = module.compute_host.asg_name } }],
          ]
          yAxis = {}
        }
      },
      {
        type = "metric"
        properties = {
          view    = "timeSeries"
          stacked = false
          region  = data.aws_region.current.region
          title   = "ALB Metrics"
          period  = 60
          stat    = "Sum"
          metrics = [
            ["AWS/ApplicationELB", "RequestCount", { label = "Requests", stat = "Sum", region = data.aws_region.current.region }],
            ["AWS/ApplicationELB", "HTTPCode_ELB_5XX_Count", { label = "5XX", stat = "Sum", region = data.aws_region.current.region }],
            ["AWS/ApplicationELB", "TargetResponseTime", { label = "Avg Response Time", stat = "Average", region = data.aws_region.current.region }],
          ]
          yAxis = {}
        }
      },
      {
        type = "metric"
        properties = {
          view    = "timeSeries"
          stacked = false
          region  = data.aws_region.current.region
          title   = "Aurora PostgreSQL"
          period  = 60
          stat    = "Average"
          metrics = [
            ["AWS/RDS", "DatabaseConnections", { label = "Connections", stat = "Average", region = data.aws_region.current.region, dimensions = { DBClusterIdentifier = aws_rds_cluster.main.cluster_identifier } }],
            ["AWS/RDS", "CPUUtilization", { label = "CPU %", stat = "Average", region = data.aws_region.current.region, yAxis = "right", dimensions = { DBClusterIdentifier = aws_rds_cluster.main.cluster_identifier } }],
            ["AWS/RDS", "WriteIOPS", { label = "Write IOPS", stat = "Average", period = 60, region = data.aws_region.current.region, dimensions = { DBClusterIdentifier = aws_rds_cluster.main.cluster_identifier } }],
            ["AWS/RDS", "ReadIOPS", { label = "Read IOPS", stat = "Average", period = 60, region = data.aws_region.current.region, dimensions = { DBClusterIdentifier = aws_rds_cluster.main.cluster_identifier } }],
          ]
          yAxis = {}
        }
      },
      {
        type = "metric"
        properties = {
          view    = "timeSeries"
          stacked = false
          region  = data.aws_region.current.region
          title   = "NAT Gateway"
          period  = 60
          stat    = "Sum"
          metrics = [
            ["AWS/NATGateway", "BytesOutToDestination", { label = "Outbound", stat = "Sum", region = data.aws_region.current.region }],
            ["AWS/NATGateway", "BytesInFromDestination", { label = "Inbound", stat = "Sum", region = data.aws_region.current.region }],
          ]
          yAxis = {}
        }
      },
    ]
  })
}

# --- Dedicated staging EKS cluster (decoupled from production) ---

module "eks" {
  source = "../modules/pico-eks"

  project_name       = var.project_name
  environment        = var.environment
  vpc_id             = module.vpc.vpc_id
  private_subnet_ids = module.vpc.private_subnet_ids

  fargate_namespaces = ["api", "monitoring"]

  common_tags = local.common_tags
}

# API token comes from SSM at apply time and is projected into the pod
# via a Kubernetes secret. The container reads PICO_API_TOKEN directly.
data "aws_ssm_parameter" "api_token" {
  name            = var.pico_api_token_parameter_name
  with_decryption = true
}

# --- Kubernetes Resources ---

resource "kubernetes_namespace" "api" {
  metadata {
    name = "api"
  }

  depends_on = [module.eks]
}

resource "kubernetes_secret" "api" {
  metadata {
    name      = "api"
    namespace = kubernetes_namespace.api.metadata[0].name
  }

  data = {
    PICO_API_TOKEN = data.aws_ssm_parameter.api_token.value
  }

  type = "Opaque"

  depends_on = [module.eks]
}

resource "kubernetes_deployment" "api" {
  metadata {
    name      = "api"
    namespace = kubernetes_namespace.api.metadata[0].name
    labels = {
      app = "api"
    }
  }
  spec {
    replicas = var.api_desired_count
    selector {
      match_labels = {
        app = "api"
      }
    }
    template {
      metadata {
        labels = {
          app = "api"
        }
      }
      spec {
        service_account_name = kubernetes_service_account.api.metadata[0].name
        container {
          name = "api"
          # Immutable per-revision tag. CI must push
          # ${module.eks.ecr_repository_url}:${var.commit} before apply.
          image = "${module.eks.ecr_repository_url}:${var.commit}"
          port {
            container_port = 8080
          }
          resources {
            requests = {
              cpu    = "256m"
              memory = "512Mi"
            }
            limits = {
              memory = "1Gi"
            }
          }
          env {
            name  = "RUN_ENV"
            value = "production"
          }
          env {
            name  = "PICO_RUNTIME"
            value = var.runtime
          }
          env {
            name  = "PICO_IDLE_TIMEOUT_SECS"
            value = tostring(var.idle_timeout_secs)
          }
          env {
            name = "PICO_API_TOKEN"
            value_from {
              secret_key_ref {
                name = kubernetes_secret.api.metadata[0].name
                key  = "PICO_API_TOKEN"
              }
            }
          }
          env {
            name  = "API_TOKEN_PARAM"
            value = var.pico_api_token_parameter_name
          }
          env {
            # Reserved for future DB-backed control plane. Unused by pico-api today.
            name  = "DB_SECRET_ARN"
            value = aws_rds_cluster.main.master_user_secret[0].secret_arn
          }
          env {
            name  = "DB_PORT"
            value = "5432"
          }
          env {
            # OTLP collector in monitoring namespace. Empty keeps local no-export.
            name  = "OTEL_EXPORTER_OTLP_ENDPOINT"
            value = var.otel_endpoint
          }
          liveness_probe {
            http_get {
              path = "/v1/livez"
              port = 8080
            }
            initial_delay_seconds = 60
            period_seconds        = 10
          }
          readiness_probe {
            http_get {
              path = "/v1/readyz"
              port = 8080
            }
            initial_delay_seconds = 10
            period_seconds        = 5
          }
        }
      }
    }
  }

  depends_on = [module.eks]
}

resource "kubernetes_service_account" "api" {
  metadata {
    name      = "api"
    namespace = kubernetes_namespace.api.metadata[0].name
    annotations = {
      "eks.amazonaws.com/role-arn" = aws_iam_role.api_irsa.arn
    }
  }
}

resource "kubernetes_service" "api" {
  metadata {
    name      = "api"
    namespace = kubernetes_namespace.api.metadata[0].name
  }
  spec {
    selector = {
      app = "api"
    }
    port {
      port        = 80
      target_port = 8080
      protocol    = "TCP"
    }
    type = "ClusterIP"
  }
}

resource "kubernetes_ingress_v1" "api" {
  metadata {
    name      = "api"
    namespace = kubernetes_namespace.api.metadata[0].name
    annotations = {
      "alb.ingress.kubernetes.io/scheme"      = "internal"
      "alb.ingress.kubernetes.io/target-type" = "ip"
    }
  }
  spec {
    ingress_class_name = "alb"
    rule {
      http {
        path {
          path      = "/"
          path_type = "Prefix"
          backend {
            service {
              name = kubernetes_service.api.metadata[0].name
              port {
                number = 80
              }
            }
          }
        }
      }
    }
  }

  depends_on = [module.eks]
}

resource "kubernetes_service" "api_nlb" {
  metadata {
    name      = "api-nlb"
    namespace = kubernetes_namespace.api.metadata[0].name
    annotations = {
      "service.beta.kubernetes.io/aws-load-balancer-type"   = "nlb"
      "service.beta.kubernetes.io/aws-load-balancer-scheme" = "internal"
      "service.beta.kubernetes.io/aws-load-balancer-name"   = "${local.name_prefix}-api-nlb"
    }
  }
  spec {
    type = "LoadBalancer"
    selector = {
      app = "api"
    }
    port {
      port        = 80
      target_port = 8080
      protocol    = "TCP"
    }
  }

  depends_on = [module.eks]
}

# --- Observability stack (staging self-hosted) ---
# Prometheus + Grafana via kube-prometheus-stack, OTLP via
# opentelemetry-collector. The collector Service is an internal NLB so
# EC2 compute hosts (outside the cluster) can export OTLP; in-cluster
# pods use the ClusterIP DNS via var.otel_endpoint.

resource "kubernetes_namespace" "monitoring" {
  count = var.enable_observability ? 1 : 0

  metadata {
    name = "monitoring"
  }

  depends_on = [module.eks]
}

resource "helm_release" "kube_prometheus_stack" {
  count = var.enable_observability ? 1 : 0

  name       = "kube-prometheus-stack"
  namespace  = kubernetes_namespace.monitoring[0].metadata[0].name
  repository = "https://prometheus-community.github.io/helm-charts"
  chart      = "kube-prometheus-stack"

  # Fargate-compatible staging defaults: no hostPath persistence,
  # short retention, Grafana sidecar loads pico dashboards from ConfigMaps.
  values = [yamlencode({
    prometheus = {
      prometheusSpec = {
        retention                               = "6h"
        storageSpec                             = null
        serviceMonitorSelectorNilUsesHelmValues = false
        podMonitorSelectorNilUsesHelmValues     = false
        ruleSelectorNilUsesHelmValues           = false
      }
    }
    alertmanager = {
      enabled = true
    }
    grafana = {
      enabled = true
      sidecar = {
        dashboards = {
          enabled    = true
          label      = "grafana_dashboard"
          labelValue = "pico"
        }
      }
    }
  })]

  depends_on = [module.eks]
}

resource "helm_release" "opentelemetry_collector" {
  count = var.enable_observability ? 1 : 0

  name       = "opentelemetry-collector"
  namespace  = kubernetes_namespace.monitoring[0].metadata[0].name
  repository = "https://open-telemetry.github.io/opentelemetry-helm-charts"
  chart      = "opentelemetry-collector"

  # OTLP in (4317/4318), Prometheus out (8889). The Service is an
  # internal NLB so EC2 compute hosts can reach OTLP from outside the
  # cluster; in-cluster pods keep using the ClusterIP DNS.
  values = [yamlencode({
    mode = "deployment"
    service = {
      enabled = true
      type    = "LoadBalancer"
      annotations = {
        "service.beta.kubernetes.io/aws-load-balancer-type"   = "nlb"
        "service.beta.kubernetes.io/aws-load-balancer-scheme" = "internal"
        "service.beta.kubernetes.io/aws-load-balancer-name"   = "${local.name_prefix}-otel"
      }
    }
    config = {
      receivers = {
        otlp = {
          protocols = {
            grpc = { endpoint = "0.0.0.0:4317" }
            http = { endpoint = "0.0.0.0:4318" }
          }
        }
      }
      processors = {
        batch = {}
        memory_limiter = {
          check_interval = "5s"
          limit_mib      = 512
        }
      }
      exporters = {
        prometheus = {
          endpoint = "0.0.0.0:8889"
        }
      }
      service = {
        pipelines = {
          metrics = {
            receivers  = ["otlp"]
            processors = ["memory_limiter", "batch"]
            exporters  = ["prometheus"]
          }
          traces = {
            receivers  = ["otlp"]
            processors = ["memory_limiter", "batch"]
            exporters  = ["prometheus"]
          }
        }
      }
    }
    ports = {
      otlp-grpc = {
        enabled       = true
        containerPort = 4317
        servicePort   = 4317
        protocol      = "TCP"
      }
      prometheus = {
        enabled       = true
        containerPort = 8889
        servicePort   = 8889
        protocol      = "TCP"
      }
    }
  })]

  depends_on = [module.eks]
}

# Grafana sidecar picks up ConfigMaps labelled grafana_dashboard=pico.
resource "kubernetes_config_map" "grafana_dashboards" {
  count = var.enable_observability ? 1 : 0

  metadata {
    name      = "pico-dashboards"
    namespace = kubernetes_namespace.monitoring[0].metadata[0].name
    labels = {
      grafana_dashboard = "pico"
    }
  }

  data = {
    for f in fileset("${path.module}/../../../o11y", "*.json") :
    f => file("${path.module}/../../../o11y/${f}")
  }

  depends_on = [module.eks]
}

# Recording and burn alerts. The prometheus-operator picks up
# PrometheusRule CRs when ruleSelectorNilUsesHelmValues is false.
resource "kubernetes_manifest" "pico_recording_rules" {
  count = var.enable_observability ? 1 : 0

  manifest = yamldecode(file("${path.module}/../../../o11y/rules/pico-recording-rules.yaml"))

  depends_on = [helm_release.kube_prometheus_stack]
}

# Internal NLB fronting the collector (created by the chart Service).
# Same wait pattern as the API NLB: the LB controller provisions async.
resource "time_sleep" "wait_for_otel" {
  count = var.enable_observability ? 1 : 0

  depends_on      = [helm_release.opentelemetry_collector]
  create_duration = "120s"
}

data "aws_lb" "otel" {
  count = var.enable_observability ? 1 : 0

  depends_on = [time_sleep.wait_for_otel]
  name       = "${local.name_prefix}-otel"
}

# OTLP gRPC from compute hosts to the cluster (Fargate pod ENIs).
resource "aws_vpc_security_group_ingress_rule" "otel_otlp_from_compute" {
  count = var.enable_observability ? 1 : 0

  security_group_id            = module.eks.cluster_security_group_id
  description                  = "OTLP gRPC from compute hosts"
  from_port                    = 4317
  to_port                      = 4317
  ip_protocol                  = "tcp"
  referenced_security_group_id = module.compute_host.security_group_id
}

# --- Compute Host Module ---

module "compute_host" {
  source = "../modules/pico-compute-host"

  project_name       = var.project_name
  environment        = var.environment
  vpc_id             = module.vpc.vpc_id
  private_subnet_ids = module.vpc.private_subnet_ids

  instance_type             = var.instance_type
  use_spot                  = var.use_spot
  ebs_volume_size           = var.ebs_volume_size
  asg_min_size              = var.asg_min_size
  asg_max_size              = var.asg_max_size
  asg_desired_size          = var.asg_desired_size
  cpu_target_tracking_value = var.cpu_target_tracking_value

  key_pair_name     = var.key_pair_name
  ssh_allowed_cidrs = var.ssh_allowed_cidrs
  enable_ssm        = var.enable_ssm

  domain_name = var.domain_name
  runtime     = var.runtime
  commit      = var.commit

  asset_cache_bucket      = aws_s3_bucket.artifacts.id
  asset_cache_prefix      = var.asset_cache_prefix
  idle_timeout_secs       = var.idle_timeout_secs
  additional_kms_key_arns = [aws_kms_key.artifacts.arn, aws_kms_key.snapshots.arn]

  # Host OTLP via the internal collector NLB. Empty keeps local no-export.
  otel_endpoint = var.enable_observability ? "http://${data.aws_lb.otel[0].dns_name}:4317" : ""

  control_plane_security_group_id = module.eks.cluster_security_group_id
  alarm_sns_topic_arn             = aws_sns_topic.alarms.arn
}

# --- Database SG ingress (defined after EKS module to avoid circular dep) ---

resource "aws_vpc_security_group_ingress_rule" "db_postgres_from_eks" {
  security_group_id            = aws_security_group.database.id
  description                  = "PostgreSQL from EKS cluster"
  from_port                    = 5432
  to_port                      = 5432
  ip_protocol                  = "tcp"
  referenced_security_group_id = module.eks.cluster_security_group_id
}

# --- API Gateway (REST) ---

resource "aws_api_gateway_rest_api" "main" {
  name = "${local.name_prefix}-api"
  endpoint_configuration {
    types = ["REGIONAL"]
  }
  tags = local.common_tags
}

resource "time_sleep" "wait_for_nlb" {
  depends_on      = [kubernetes_service.api_nlb]
  create_duration = "120s"
}

data "aws_lb" "api_nlb" {
  depends_on = [time_sleep.wait_for_nlb]
  name       = "${local.name_prefix}-api-nlb"
}

resource "aws_api_gateway_vpc_link" "main" {
  name        = "${local.name_prefix}-vpc-link"
  target_arns = [data.aws_lb.api_nlb.arn]
  tags        = local.common_tags
}

resource "aws_api_gateway_resource" "proxy" {
  rest_api_id = aws_api_gateway_rest_api.main.id
  parent_id   = aws_api_gateway_rest_api.main.root_resource_id
  path_part   = "{proxy+}"
}

resource "aws_api_gateway_method" "root" {
  rest_api_id   = aws_api_gateway_rest_api.main.id
  resource_id   = aws_api_gateway_rest_api.main.root_resource_id
  http_method   = "ANY"
  authorization = "NONE"
}

resource "aws_api_gateway_method" "proxy" {
  rest_api_id   = aws_api_gateway_rest_api.main.id
  resource_id   = aws_api_gateway_resource.proxy.id
  http_method   = "ANY"
  authorization = "NONE"
}

resource "aws_api_gateway_integration" "root" {
  rest_api_id             = aws_api_gateway_rest_api.main.id
  resource_id             = aws_api_gateway_rest_api.main.root_resource_id
  http_method             = aws_api_gateway_method.root.http_method
  type                    = "HTTP_PROXY"
  integration_http_method = "ANY"
  uri                     = "http://${data.aws_lb.api_nlb.dns_name}:80/"
  connection_type         = "VPC_LINK"
  connection_id           = aws_api_gateway_vpc_link.main.id
}

resource "aws_api_gateway_integration" "proxy" {
  rest_api_id             = aws_api_gateway_rest_api.main.id
  resource_id             = aws_api_gateway_resource.proxy.id
  http_method             = aws_api_gateway_method.proxy.http_method
  type                    = "HTTP_PROXY"
  integration_http_method = "ANY"
  uri                     = "http://${data.aws_lb.api_nlb.dns_name}:80/{proxy}"
  connection_type         = "VPC_LINK"
  connection_id           = aws_api_gateway_vpc_link.main.id
}

resource "aws_api_gateway_deployment" "main" {
  depends_on = [
    aws_api_gateway_integration.root,
    aws_api_gateway_integration.proxy,
  ]
  rest_api_id = aws_api_gateway_rest_api.main.id
  triggers = {
    redeployment = sha1(jsonencode([
      aws_api_gateway_integration.root.id,
      aws_api_gateway_integration.proxy.id,
    ]))
  }
}

resource "aws_api_gateway_stage" "main" {
  deployment_id = aws_api_gateway_deployment.main.id
  rest_api_id   = aws_api_gateway_rest_api.main.id
  stage_name    = var.environment
  tags          = local.common_tags
}

resource "aws_api_gateway_usage_plan" "main" {
  name = "${local.name_prefix}-usage-plan"
  api_stages {
    api_id = aws_api_gateway_rest_api.main.id
    stage  = aws_api_gateway_stage.main.stage_name
  }
  tags = local.common_tags
}

resource "aws_api_gateway_api_key" "main" {
  name = "${local.name_prefix}-api-key"
  tags = local.common_tags
}

resource "aws_api_gateway_usage_plan_key" "main" {
  key_id        = aws_api_gateway_api_key.main.id
  key_type      = "API_KEY"
  usage_plan_id = aws_api_gateway_usage_plan.main.id
}

# --- ACM Certificate for API Gateway ---

resource "aws_acm_certificate" "api" {
  domain_name       = var.domain_name
  validation_method = "DNS"

  tags = local.common_tags

  lifecycle {
    create_before_destroy = true
  }
}

data "cloudflare_zone" "main" {
  zone_id = var.cloudflare_zone_id
}

resource "cloudflare_dns_record" "acm_validation" {
  for_each = {
    for dvo in aws_acm_certificate.api.domain_validation_options : dvo.domain_name => {
      name  = dvo.resource_record_name
      value = dvo.resource_record_value
      type  = dvo.resource_record_type
    }
  }

  zone_id = var.cloudflare_zone_id
  name    = each.value.name
  content = trimsuffix(each.value.value, ".")
  type    = each.value.type
  ttl     = 60
  proxied = false
}

resource "aws_acm_certificate_validation" "api" {
  certificate_arn         = aws_acm_certificate.api.arn
  validation_record_fqdns = [for record in cloudflare_dns_record.acm_validation : record.hostname]
}

# --- API Gateway Custom Domain ---

resource "aws_api_gateway_domain_name" "api" {
  domain_name              = var.domain_name
  regional_certificate_arn = aws_acm_certificate_validation.api.certificate_arn

  endpoint_configuration {
    types = ["REGIONAL"]
  }

  depends_on = [aws_acm_certificate_validation.api]
}

resource "aws_api_gateway_base_path_mapping" "api" {
  api_id      = aws_api_gateway_rest_api.main.id
  stage_name  = aws_api_gateway_stage.main.stage_name
  domain_name = aws_api_gateway_domain_name.api.domain_name
}

# --- Cloudflare DNS ---

resource "cloudflare_dns_record" "api" {
  zone_id = var.cloudflare_zone_id
  name    = trimsuffix(var.domain_name, ".${data.cloudflare_zone.main.name}")
  content = aws_api_gateway_domain_name.api.regional_domain_name
  type    = "CNAME"
  ttl     = 1
  proxied = var.cloudflare_proxy_api
}

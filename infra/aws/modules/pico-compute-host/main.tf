locals {
  graviton_prefixes = ["m6g", "m7g", "m8g", "c6g", "c7g", "c8g", "r6g", "r7g", "r8g"]
  arch_suffix       = anytrue([for p in local.graviton_prefixes : startswith(var.instance_type, p)]) ? "arm64" : "amd64"
  arch              = local.arch_suffix == "arm64" ? "aarch64" : "x86_64"
  name_prefix       = "${var.project_name}-${var.environment}"
  common_tags = {
    Project     = var.project_name
    Environment = var.environment
    ManagedBy   = "terraform"
  }

  pico_cloud_init = templatefile("${path.module}/templates/cloud-init.yaml.tftpl", {
    aws_region         = data.aws_region.current.region
    domain_name        = var.domain_name
    runtime            = var.runtime
    arch               = local.arch
    idle_timeout_secs  = var.idle_timeout_secs
    asset_cache_bucket = var.asset_cache_bucket
    asset_cache_prefix = var.asset_cache_prefix
    commit             = var.commit
    environment        = var.environment
    otel_endpoint      = var.otel_endpoint
  })
}

data "aws_region" "current" {}

data "aws_caller_identity" "current" {}

data "aws_partition" "current" {}

data "aws_availability_zones" "available" {
  state = "available"
}

data "aws_ami" "picocompute" {
  most_recent = true
  owners      = ["self"]

  filter {
    name   = "name"
    values = ["pico-compute-${local.arch}-*"]
  }

  filter {
    name   = "tag:Arch"
    values = [local.arch]
  }
}

data "aws_ami" "ubuntu" {
  most_recent = true
  owners      = ["099720109477"]

  filter {
    name   = "name"
    values = ["ubuntu/images/hvm-ssd-gp3/*24.04-${local.arch_suffix}-server-*"]
  }

  filter {
    name   = "architecture"
    values = [local.arch_suffix == "arm64" ? "arm64" : "x86_64"]
  }

  filter {
    name   = "root-device-type"
    values = ["ebs"]
  }

  filter {
    name   = "virtualization-type"
    values = ["hvm"]
  }
}

locals {
  # Fail closed when the Packer AMI is missing. Do not silently fall back
  # to vanilla Ubuntu: it lacks Firecracker/KVM setup and would fail
  # bootstrap preconditions. Build infra/packer/compute-host.pkr.hcl first.
  ami_id = data.aws_ami.picocompute.id
}

# --- Security Group ---

resource "aws_security_group" "compute" {
  name        = "${local.name_prefix}-compute-sg"
  description = "PicoCompute compute host access"
  vpc_id      = var.vpc_id

  dynamic "ingress" {
    for_each = var.ssh_allowed_cidrs
    content {
      description = "SSH"
      from_port   = 22
      to_port     = 22
      protocol    = "tcp"
      cidr_blocks = [ingress.value]
    }
  }

  dynamic "ingress" {
    for_each = var.control_plane_security_group_id != "" ? [1] : []
    content {
      description     = "Control plane traffic"
      from_port       = 0
      to_port         = 0
      protocol        = "-1"
      security_groups = [var.control_plane_security_group_id]
    }
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = merge(local.common_tags, {
    Name = "${local.name_prefix}-compute-sg"
  })
}

# --- IAM ---

data "aws_iam_policy_document" "ec2_assume_role" {
  statement {
    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = ["ec2.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "compute" {
  name               = "${local.name_prefix}-compute-role"
  assume_role_policy = data.aws_iam_policy_document.ec2_assume_role.json

  tags = merge(local.common_tags, {
    Name = "${local.name_prefix}-compute-role"
  })
}

resource "aws_iam_role_policy_attachment" "ssm" {
  count = var.enable_ssm ? 1 : 0

  role       = aws_iam_role.compute.name
  policy_arn = "arn:${data.aws_partition.current.partition}:iam::aws:policy/AmazonSSMManagedInstanceCore"
}

data "aws_iam_policy_document" "bootstrap_secret_access" {
  dynamic "statement" {
    for_each = length(var.additional_kms_key_arns) > 0 ? [1] : []
    content {
      actions = [
        "kms:Decrypt",
        "kms:GenerateDataKey",
        "kms:DescribeKey",
      ]
      resources = var.additional_kms_key_arns
    }
  }
}

resource "aws_iam_role_policy" "bootstrap_secret_access" {
  name   = "${local.name_prefix}-bootstrap-secret-access"
  role   = aws_iam_role.compute.id
  policy = data.aws_iam_policy_document.bootstrap_secret_access.json
}

data "aws_iam_policy_document" "s3_asset_cache" {
  count = var.asset_cache_bucket != "" ? 1 : 0

  statement {
    actions = [
      "s3:GetObject",
      "s3:PutObject",
    ]
    resources = [
      "arn:${data.aws_partition.current.partition}:s3:::${var.asset_cache_bucket}/${var.asset_cache_prefix}/*",
    ]
  }

  statement {
    actions = [
      "s3:ListBucket",
    ]
    resources = [
      "arn:${data.aws_partition.current.partition}:s3:::${var.asset_cache_bucket}",
    ]
  }
}

resource "aws_iam_role_policy" "s3_asset_cache" {
  count = var.asset_cache_bucket != "" ? 1 : 0

  name   = "${local.name_prefix}-s3-asset-cache"
  role   = aws_iam_role.compute.id
  policy = data.aws_iam_policy_document.s3_asset_cache[0].json
}

resource "aws_iam_instance_profile" "compute" {
  name = "${local.name_prefix}-compute-profile"
  role = aws_iam_role.compute.name

  tags = merge(local.common_tags, {
    Name = "${local.name_prefix}-compute-profile"
  })
}

# --- Launch Template ---

resource "aws_launch_template" "compute" {
  name_prefix = "${local.name_prefix}-compute-lt-"

  image_id      = local.ami_id
  instance_type = var.instance_type
  key_name      = var.key_pair_name

  iam_instance_profile {
    name = aws_iam_instance_profile.compute.name
  }

  vpc_security_group_ids = [aws_security_group.compute.id]

  user_data = base64encode(local.pico_cloud_init)

  block_device_mappings {
    device_name = data.aws_ami.ubuntu.root_device_name
    ebs {
      volume_type           = "gp3"
      volume_size           = var.ebs_volume_size
      delete_on_termination = true
      encrypted             = true
    }
  }

  dynamic "cpu_options" {
    for_each = endswith(var.instance_type, ".metal") ? [] : [1]
    content {
      nested_virtualization = "enabled"
    }
  }

  dynamic "instance_market_options" {
    for_each = var.use_spot ? [1] : []
    content {
      market_type = "spot"
    }
  }

  monitoring {
    enabled = true
  }

  metadata_options {
    http_endpoint               = "enabled"
    http_tokens                 = "required"
    instance_metadata_tags      = "enabled"
    http_put_response_hop_limit = 2
  }

  tag_specifications {
    resource_type = "instance"
    tags = merge(local.common_tags, {
      Name = "${local.name_prefix}-compute"
    })
  }

  lifecycle {
    create_before_destroy = true
  }
}

# --- Auto Scaling ---

resource "aws_autoscaling_group" "compute" {
  name                = "${local.name_prefix}-compute-asg"
  vpc_zone_identifier = var.private_subnet_ids
  min_size            = var.asg_min_size
  max_size            = var.asg_max_size
  desired_capacity    = var.asg_desired_size

  health_check_type         = "ELB"
  health_check_grace_period = 1800
  default_instance_warmup   = 300
  default_cooldown          = 180

  launch_template {
    id      = aws_launch_template.compute.id
    version = aws_launch_template.compute.latest_version
  }

  instance_refresh {
    strategy = "Rolling"
    preferences {
      min_healthy_percentage = 90
    }
  }

  tag {
    key                 = "Name"
    value               = "${local.name_prefix}-compute"
    propagate_at_launch = true
  }

  lifecycle {
    ignore_changes = [desired_capacity]
  }
}

resource "aws_autoscaling_policy" "cpu_target_tracking" {
  name                      = "${local.name_prefix}-compute-cpu-tt"
  autoscaling_group_name    = aws_autoscaling_group.compute.name
  policy_type               = "TargetTrackingScaling"
  estimated_instance_warmup = 300

  target_tracking_configuration {
    target_value = var.cpu_target_tracking_value

    predefined_metric_specification {
      predefined_metric_type = "ASGAverageCPUUtilization"
    }
  }
}

resource "aws_cloudwatch_metric_alarm" "asg_no_healthy_instances" {
  alarm_name          = "${local.name_prefix}-compute-asg-no-healthy-instances"
  comparison_operator = "LessThanThreshold"
  evaluation_periods  = 2
  metric_name         = "GroupInServiceInstances"
  namespace           = "AWS/AutoScaling"
  period              = 60
  statistic           = "Average"
  threshold           = 1
  alarm_description   = "Compute ASG has fewer than 1 in-service instance"
  actions_enabled     = var.alarm_sns_topic_arn != ""

  alarm_actions = var.alarm_sns_topic_arn != "" ? [var.alarm_sns_topic_arn] : []
  ok_actions    = var.alarm_sns_topic_arn != "" ? [var.alarm_sns_topic_arn] : []

  dimensions = {
    AutoScalingGroupName = aws_autoscaling_group.compute.name
  }

  tags = merge(local.common_tags, {
    Name = "${local.name_prefix}-compute-asg-health"
  })
}

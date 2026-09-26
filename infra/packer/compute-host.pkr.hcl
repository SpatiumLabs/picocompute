packer {
  required_plugins {
    amazon = {
      version = ">= 0"
      source  = "github.com/hashicorp/amazon"
    }
  }
}

variable "aws_region" {
  type    = string
  default = "us-east-1"
}

variable "arch" {
  type    = string
  default = "x86_64"
  validation {
    condition     = contains(["x86_64", "aarch64"], var.arch)
    error_message = "arch must be x86_64 or aarch64."
  }
}

variable "firecracker_version" {
  type    = string
  default = "latest"
}

locals {
  instance_type = var.arch == "aarch64" ? "t4g.medium" : "t3.medium"

  source_ami_filter = var.arch == "aarch64" ? {
    name   = "ubuntu/images/hvm-ssd-gp3/*26.04-arm64-server-*"
    owners = ["099720109477"]
  } : {
    name   = "ubuntu/images/hvm-ssd-gp3/*26.04-amd64-server-*"
    owners = ["099720109477"]
  }

  fc_arch = var.arch == "aarch64" ? "aarch64" : "x86_64"
}

source "amazon-ebs" "compute" {
  region       = var.aws_region
  instance_type = local.instance_type
  source_ami_filter {
    filters = {
      name                = local.source_ami_filter.name
      root-device-type    = "ebs"
      virtualization-type = "hvm"
    }
    owners      = local.source_ami_filter.owners
    most_recent = true
  }

  ami_name        = "pico-compute-${var.arch}-{{isotime \"2006-01-02-1504\"}}"
  ami_description = "PicoCompute compute host (Ubuntu 26.04) with Firecracker and KVM pre-installed"

  ssh_username = "ubuntu"

  launch_block_device_mappings {
    device_name = "/dev/sda1"
    volume_size = 20
    volume_type = "gp3"
    encrypted   = true
  }

  tags = {
    Name        = "pico-compute-host"
    Arch        = var.arch
    ManagedBy   = "packer"
    BuiltAt     = "{{isotime \"2006-01-02T15:04:05Z07:00\"}}"
  }
}

build {
  sources = ["source.amazon-ebs.compute"]

  provisioner "shell" {
    inline = [
      "sudo apt-get update",
      "sudo DEBIAN_FRONTEND=noninteractive apt-get install -y awscli curl unzip e2fsprogs util-linux qemu-system-x86",
      # KVM
      "sudo modprobe kvm || true",
      "if [ '${var.arch}' != 'aarch64' ]; then sudo modprobe kvm_intel nested=1 || true; fi",
      "echo 'kvm' | sudo tee /etc/modules-load.d/pico-kvm.conf > /dev/null",
      "if [ '${var.arch}' != 'aarch64' ]; then echo 'kvm_intel' | sudo tee -a /etc/modules-load.d/pico-kvm.conf > /dev/null; fi",
      "echo 'KERNEL==\"kvm\", GROUP=\"kvm\", MODE=\"0660\"' | sudo tee /etc/udev/rules.d/99-kvm.rules > /dev/null",
      # Firecracker
      "FC_ARCH=${local.fc_arch}",
      "if [ '${var.firecracker_version}' = 'latest' ]; then",
      "  FC_TAG=$(curl -fsSL https://api.github.com/repos/firecracker-microvm/firecracker/releases/latest | grep -o '\"tag_name\": *\"[^\"]*\"' | head -1 | sed 's/.*\"\\([^\"]*\\)\".*/\\1/')",
      "else",
      "  FC_TAG=${var.firecracker_version}",
      "fi",
      "FC_URL=\"https://github.com/firecracker-microvm/firecracker/releases/download/$FC_TAG/firecracker-$FC_TAG-$FC_ARCH.tgz\"",
      "FC_CHECKSUM_URL=\"https://github.com/firecracker-microvm/firecracker/releases/download/$FC_TAG/SHA256SUMS\"",
      "curl -fsSL \"$FC_URL\" -o /tmp/firecracker.tgz",
      "curl -fsSL \"$FC_CHECKSUM_URL\" -o /tmp/SHA256SUMS",
      "(cd /tmp && sha256sum --ignore-missing -c SHA256SUMS)",
      "tar -xzf /tmp/firecracker.tgz -C /tmp",
      "sudo install -m0755 $(find /tmp -type f -name 'firecracker-*-'$FC_ARCH ! -name '*jailer*' | head -n 1) /usr/local/bin/firecracker",
      "rm -f /tmp/firecracker.tgz /tmp/SHA256SUMS /tmp/firecracker-* 2>/dev/null || true",
      # Directories
      "sudo mkdir -p /opt/pico/bin /opt/pico/image/x86_64 /opt/pico/image/aarch64 /var/lib/pico/workspaces /etc/pico",
    ]
  }
}

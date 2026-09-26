terraform {
  required_version = ">= 1.15"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 6.49"
    }

    cloudflare = {
      source  = "cloudflare/cloudflare"
      version = "~> 5.19"
    }

    kubernetes = {
      source  = "hashicorp/kubernetes"
      version = "~> 2.35"
    }

    tls = {
      source  = "hashicorp/tls"
      version = "~> 4.0"
    }

    time = {
      source  = "hashicorp/time"
      version = "~> 0.12"
    }
  }

  backend "s3" {}
}

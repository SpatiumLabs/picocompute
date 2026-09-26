variable "project_name" {
  description = "Resource naming prefix."
  type        = string
  default     = "picocompute"
}

variable "environment" {
  description = "Environment tag applied to all resources."
  type        = string
}

variable "vpc_cidr" {
  description = "CIDR block for the VPC."
  type        = string
}

variable "availability_zones" {
  description = "List of availability zone names for subnet placement."
  type        = list(string)
}

variable "common_tags" {
  description = "Tags applied to all taggable resources."
  type        = map(string)
  default     = {}
}

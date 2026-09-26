bucket = "pico-terraform-state"
key    = "aws/staging/terraform.tfstate"
region = "auto"
profile = "r2"
shared_credentials_files = ["~/.aws/credentials"]

endpoints = {
  s3 = "https://bb4d54a34a3f12448259dacfb0d2cdcd.r2.cloudflarestorage.com"
}

use_path_style              = true
skip_credentials_validation = true
skip_metadata_api_check     = true
skip_region_validation      = true
skip_requesting_account_id  = true
skip_s3_checksum            = true

# Aethelred Testnet Environment
# Deploys 4 validators on AWS with Nitro Enclave support

terraform {
  required_version = ">= 1.5.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }

  backend "s3" {
    bucket         = "aethelred-testnet-terraform-state"
    key            = "testnet/terraform.tfstate"
    region         = "us-east-1"
    dynamodb_table = "aethelred-testnet-terraform-locks"
    encrypt        = true
  }
}

provider "aws" {
  region = var.region

  default_tags {
    tags = {
      Project     = "Aethelred"
      Environment = var.environment
      ManagedBy   = "Terraform"
      ChainID     = var.chain_id
    }
  }
}

locals {
  public_dns_zone_enabled = trimspace(var.public_dns_zone_name) != ""
  public_dns_records      = { for name, target in var.public_dns_records : name => trimspace(target) if trimspace(target) != "" }
}

data "aws_route53_zone" "public_testnet" {
  count        = local.public_dns_zone_enabled ? 1 : 0
  name         = var.public_dns_zone_name
  private_zone = false
}

resource "aws_route53_record" "public_testnet" {
  for_each = local.public_dns_zone_enabled ? local.public_dns_records : {}

  zone_id = data.aws_route53_zone.public_testnet[0].zone_id
  name    = "${each.key}.${trim(var.public_dns_zone_name, \".\")}"
  type    = "CNAME"
  ttl     = var.public_dns_ttl
  records = [each.value]
}

# -----------------------------------------------------------------------------
# Validator cluster
# -----------------------------------------------------------------------------
module "validators" {
  source = "../../modules/validator"

  environment          = var.environment
  validator_count      = var.validator_count
  instance_type        = var.instance_type
  nitro_instance_type  = var.nitro_instance_type
  enable_nitro_enclaves = var.enable_nitro_enclaves
  enable_sgx           = var.enable_sgx
  vpc_id               = var.vpc_id
  subnet_ids           = var.subnet_ids
  ssh_key_name         = var.ssh_key_name
  ebs_volume_size      = var.ebs_volume_size

  tags = {
    ChainID = var.chain_id
  }
}

# -----------------------------------------------------------------------------
# Outputs
# -----------------------------------------------------------------------------
output "validator_security_group_id" {
  description = "Security group ID for testnet validators"
  value       = module.validators.security_group_id
}

output "validator_iam_role_arn" {
  description = "IAM role ARN for testnet validators"
  value       = module.validators.iam_role_arn
}

output "validator_kms_key_id" {
  description = "KMS key ID used for encryption"
  value       = module.validators.kms_key_id
}

output "validator_s3_bucket" {
  description = "S3 bucket for validator state"
  value       = module.validators.s3_bucket_name
}

output "validator_asg_name" {
  description = "Auto Scaling Group name"
  value       = module.validators.autoscaling_group_name
}

output "public_testnet_dns_records" {
  description = "Public Route53 records created for the testnet operator endpoints"
  value = {
    for name, record in aws_route53_record.public_testnet :
    name => record.fqdn
  }
}

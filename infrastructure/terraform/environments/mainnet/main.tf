# Aethelred Mainnet Environment
# Deploys 7 validators across multiple AZs with hardened security

terraform {
  required_version = ">= 1.5.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }

  backend "s3" {
    bucket         = "aethelred-mainnet-terraform-state"
    key            = "mainnet/terraform.tfstate"
    region         = "us-east-1"
    dynamodb_table = "aethelred-mainnet-terraform-locks"
    encrypt        = true
  }
}

# -----------------------------------------------------------------------------
# Providers — primary and secondary region
# -----------------------------------------------------------------------------
provider "aws" {
  region = var.primary_region

  default_tags {
    tags = {
      Project     = "Aethelred"
      Environment = var.environment
      ManagedBy   = "Terraform"
      ChainID     = var.chain_id
    }
  }
}

provider "aws" {
  alias  = "secondary"
  region = var.secondary_region

  default_tags {
    tags = {
      Project     = "Aethelred"
      Environment = var.environment
      ManagedBy   = "Terraform"
      ChainID     = var.chain_id
    }
  }
}

# -----------------------------------------------------------------------------
# Primary region validators (5 of 7)
# -----------------------------------------------------------------------------
module "validators_primary" {
  source = "../../modules/validator"

  environment          = var.environment
  validator_count      = var.primary_validator_count
  instance_type        = var.instance_type
  nitro_instance_type  = var.nitro_instance_type
  enable_nitro_enclaves = var.enable_nitro_enclaves
  enable_sgx           = var.enable_sgx
  vpc_id               = var.primary_vpc_id
  subnet_ids           = var.primary_subnet_ids
  ssh_key_name         = var.ssh_key_name
  ebs_volume_size      = var.ebs_volume_size

  tags = {
    ChainID = var.chain_id
    Region  = var.primary_region
    Tier    = "primary"
  }
}

# -----------------------------------------------------------------------------
# Secondary region validators (2 of 7)
# -----------------------------------------------------------------------------
module "validators_secondary" {
  source = "../../modules/validator"

  providers = {
    aws = aws.secondary
  }

  environment          = var.environment
  validator_count      = var.secondary_validator_count
  instance_type        = var.instance_type
  nitro_instance_type  = var.nitro_instance_type
  enable_nitro_enclaves = var.enable_nitro_enclaves
  enable_sgx           = var.enable_sgx
  vpc_id               = var.secondary_vpc_id
  subnet_ids           = var.secondary_subnet_ids
  ssh_key_name         = var.ssh_key_name
  ebs_volume_size      = var.ebs_volume_size

  tags = {
    ChainID = var.chain_id
    Region  = var.secondary_region
    Tier    = "secondary"
  }
}

# -----------------------------------------------------------------------------
# Cross-region VPC peering
# -----------------------------------------------------------------------------
resource "aws_vpc_peering_connection" "primary_to_secondary" {
  vpc_id      = var.primary_vpc_id
  peer_vpc_id = var.secondary_vpc_id
  peer_region = var.secondary_region
  auto_accept = false

  tags = {
    Name = "aethelred-mainnet-primary-secondary-peering"
  }
}

resource "aws_vpc_peering_connection_accepter" "secondary_accept" {
  provider                  = aws.secondary
  vpc_peering_connection_id = aws_vpc_peering_connection.primary_to_secondary.id
  auto_accept               = true

  tags = {
    Name = "aethelred-mainnet-primary-secondary-peering"
  }
}

# -----------------------------------------------------------------------------
# Outputs
# -----------------------------------------------------------------------------
output "primary_security_group_id" {
  description = "Security group ID for primary region validators"
  value       = module.validators_primary.security_group_id
}

output "secondary_security_group_id" {
  description = "Security group ID for secondary region validators"
  value       = module.validators_secondary.security_group_id
}

output "primary_iam_role_arn" {
  value = module.validators_primary.iam_role_arn
}

output "secondary_iam_role_arn" {
  value = module.validators_secondary.iam_role_arn
}

output "primary_asg_name" {
  value = module.validators_primary.autoscaling_group_name
}

output "secondary_asg_name" {
  value = module.validators_secondary.autoscaling_group_name
}

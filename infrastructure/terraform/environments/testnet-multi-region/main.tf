# Aethelred Multi-Region Testnet
# Deploys validators across 3 AWS regions for geographic distribution testing

terraform {
  required_version = ">= 1.5.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }

  backend "s3" {
    bucket         = "aethelred-testnet-mr-terraform-state"
    key            = "testnet-multi-region/terraform.tfstate"
    region         = "us-east-1"
    dynamodb_table = "aethelred-testnet-mr-terraform-locks"
    encrypt        = true
  }
}

# -----------------------------------------------------------------------------
# Providers — one per region
# -----------------------------------------------------------------------------
provider "aws" {
  region = "us-east-1"

  default_tags {
    tags = {
      Project     = "Aethelred"
      Environment = "testnet"
      ManagedBy   = "Terraform"
      ChainID     = var.chain_id
      Topology    = "multi-region"
    }
  }
}

provider "aws" {
  alias  = "eu"
  region = "eu-west-1"

  default_tags {
    tags = {
      Project     = "Aethelred"
      Environment = "testnet"
      ManagedBy   = "Terraform"
      ChainID     = var.chain_id
      Topology    = "multi-region"
    }
  }
}

provider "aws" {
  alias  = "ap"
  region = "ap-southeast-1"

  default_tags {
    tags = {
      Project     = "Aethelred"
      Environment = "testnet"
      ManagedBy   = "Terraform"
      ChainID     = var.chain_id
      Topology    = "multi-region"
    }
  }
}

# -----------------------------------------------------------------------------
# Region 1 — us-east-1 (2 validators)
# -----------------------------------------------------------------------------
module "validators_us" {
  source = "../../modules/validator"

  environment          = "testnet"
  validator_count      = var.us_validator_count
  instance_type        = var.instance_type
  nitro_instance_type  = var.nitro_instance_type
  enable_nitro_enclaves = var.enable_nitro_enclaves
  enable_sgx           = false
  vpc_id               = var.us_vpc_id
  subnet_ids           = var.us_subnet_ids
  ssh_key_name         = var.ssh_key_name
  ebs_volume_size      = var.ebs_volume_size

  tags = {
    ChainID = var.chain_id
    Region  = "us-east-1"
  }
}

# -----------------------------------------------------------------------------
# Region 2 — eu-west-1 (1 validator)
# -----------------------------------------------------------------------------
module "validators_eu" {
  source = "../../modules/validator"

  providers = {
    aws = aws.eu
  }

  environment          = "testnet"
  validator_count      = var.eu_validator_count
  instance_type        = var.instance_type
  nitro_instance_type  = var.nitro_instance_type
  enable_nitro_enclaves = var.enable_nitro_enclaves
  enable_sgx           = false
  vpc_id               = var.eu_vpc_id
  subnet_ids           = var.eu_subnet_ids
  ssh_key_name         = var.ssh_key_name
  ebs_volume_size      = var.ebs_volume_size

  tags = {
    ChainID = var.chain_id
    Region  = "eu-west-1"
  }
}

# -----------------------------------------------------------------------------
# Region 3 — ap-southeast-1 (1 validator)
# -----------------------------------------------------------------------------
module "validators_ap" {
  source = "../../modules/validator"

  providers = {
    aws = aws.ap
  }

  environment          = "testnet"
  validator_count      = var.ap_validator_count
  instance_type        = var.instance_type
  nitro_instance_type  = var.nitro_instance_type
  enable_nitro_enclaves = var.enable_nitro_enclaves
  enable_sgx           = false
  vpc_id               = var.ap_vpc_id
  subnet_ids           = var.ap_subnet_ids
  ssh_key_name         = var.ssh_key_name
  ebs_volume_size      = var.ebs_volume_size

  tags = {
    ChainID = var.chain_id
    Region  = "ap-southeast-1"
  }
}

# -----------------------------------------------------------------------------
# VPC Peering: US <-> EU
# -----------------------------------------------------------------------------
resource "aws_vpc_peering_connection" "us_to_eu" {
  vpc_id      = var.us_vpc_id
  peer_vpc_id = var.eu_vpc_id
  peer_region = "eu-west-1"
  auto_accept = false

  tags = { Name = "aethelred-testnet-mr-us-eu-peering" }
}

resource "aws_vpc_peering_connection_accepter" "eu_accept_us" {
  provider                  = aws.eu
  vpc_peering_connection_id = aws_vpc_peering_connection.us_to_eu.id
  auto_accept               = true

  tags = { Name = "aethelred-testnet-mr-us-eu-peering" }
}

# -----------------------------------------------------------------------------
# VPC Peering: US <-> AP
# -----------------------------------------------------------------------------
resource "aws_vpc_peering_connection" "us_to_ap" {
  vpc_id      = var.us_vpc_id
  peer_vpc_id = var.ap_vpc_id
  peer_region = "ap-southeast-1"
  auto_accept = false

  tags = { Name = "aethelred-testnet-mr-us-ap-peering" }
}

resource "aws_vpc_peering_connection_accepter" "ap_accept_us" {
  provider                  = aws.ap
  vpc_peering_connection_id = aws_vpc_peering_connection.us_to_ap.id
  auto_accept               = true

  tags = { Name = "aethelred-testnet-mr-us-ap-peering" }
}

# -----------------------------------------------------------------------------
# VPC Peering: EU <-> AP
# -----------------------------------------------------------------------------
resource "aws_vpc_peering_connection" "eu_to_ap" {
  provider    = aws.eu
  vpc_id      = var.eu_vpc_id
  peer_vpc_id = var.ap_vpc_id
  peer_region = "ap-southeast-1"
  auto_accept = false

  tags = { Name = "aethelred-testnet-mr-eu-ap-peering" }
}

resource "aws_vpc_peering_connection_accepter" "ap_accept_eu" {
  provider                  = aws.ap
  vpc_peering_connection_id = aws_vpc_peering_connection.eu_to_ap.id
  auto_accept               = true

  tags = { Name = "aethelred-testnet-mr-eu-ap-peering" }
}

# -----------------------------------------------------------------------------
# Outputs
# -----------------------------------------------------------------------------
output "us_asg_name" {
  value = module.validators_us.autoscaling_group_name
}

output "eu_asg_name" {
  value = module.validators_eu.autoscaling_group_name
}

output "ap_asg_name" {
  value = module.validators_ap.autoscaling_group_name
}

output "peering_us_eu_id" {
  value = aws_vpc_peering_connection.us_to_eu.id
}

output "peering_us_ap_id" {
  value = aws_vpc_peering_connection.us_to_ap.id
}

output "peering_eu_ap_id" {
  value = aws_vpc_peering_connection.eu_to_ap.id
}

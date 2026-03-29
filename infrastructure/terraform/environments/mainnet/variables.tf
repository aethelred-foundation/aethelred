# Variables for Aethelred Mainnet Environment

variable "primary_region" {
  type        = string
  description = "Primary AWS region"
  default     = "us-east-1"
}

variable "secondary_region" {
  type        = string
  description = "Secondary AWS region for geo-redundancy"
  default     = "eu-west-1"
}

variable "environment" {
  type        = string
  description = "Environment name"
  default     = "mainnet"
}

variable "chain_id" {
  type        = string
  description = "Cosmos chain ID"
  default     = "aethelred-1"
}

# Validator counts — 7 total split across regions
variable "primary_validator_count" {
  type        = number
  description = "Number of validators in primary region"
  default     = 5
}

variable "secondary_validator_count" {
  type        = number
  description = "Number of validators in secondary region"
  default     = 2
}

variable "instance_type" {
  type        = string
  description = "EC2 instance type for validators"
  default     = "c5.4xlarge"
}

variable "nitro_instance_type" {
  type        = string
  description = "EC2 instance type for Nitro Enclave validators"
  default     = "c6i.8xlarge"
}

variable "enable_nitro_enclaves" {
  type        = bool
  description = "Enable Nitro Enclaves for TEE support"
  default     = true
}

variable "enable_sgx" {
  type        = bool
  description = "Enable Intel SGX instances"
  default     = false
}

variable "ebs_volume_size" {
  type        = number
  description = "EBS volume size in GB (encrypted)"
  default     = 1000
}

variable "ssh_key_name" {
  type        = string
  description = "SSH key pair name"
}

# Primary region networking
variable "primary_vpc_id" {
  type        = string
  description = "VPC ID in the primary region"
}

variable "primary_subnet_ids" {
  type        = list(string)
  description = "Subnet IDs across AZs in primary region (minimum 3 for multi-AZ)"
}

# Secondary region networking
variable "secondary_vpc_id" {
  type        = string
  description = "VPC ID in the secondary region"
}

variable "secondary_subnet_ids" {
  type        = list(string)
  description = "Subnet IDs across AZs in secondary region (minimum 2)"
}

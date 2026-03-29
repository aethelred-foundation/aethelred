# Variables for Aethelred Testnet Environment

variable "region" {
  type        = string
  description = "AWS region for testnet deployment"
  default     = "us-east-1"
}

variable "environment" {
  type        = string
  description = "Environment name"
  default     = "testnet"
}

variable "chain_id" {
  type        = string
  description = "Cosmos chain ID"
  default     = "aethelred-testnet-1"
}

variable "validator_count" {
  type        = number
  description = "Number of validator nodes"
  default     = 4
}

variable "instance_type" {
  type        = string
  description = "EC2 instance type for validators"
  default     = "c5.2xlarge"
}

variable "nitro_instance_type" {
  type        = string
  description = "EC2 instance type for Nitro Enclave validators"
  default     = "c5.4xlarge"
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

variable "vpc_id" {
  type        = string
  description = "VPC ID for testnet deployment (must be provided)"
}

variable "subnet_ids" {
  type        = list(string)
  description = "Subnet IDs across AZs for validator placement"
}

variable "ssh_key_name" {
  type        = string
  description = "SSH key pair name for validator access"
}

variable "ebs_volume_size" {
  type        = number
  description = "EBS volume size in GB for each validator"
  default     = 500
}

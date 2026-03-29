# Variables for Aethelred Multi-Region Testnet

variable "chain_id" {
  type        = string
  description = "Cosmos chain ID"
  default     = "aethelred-testnet-1"
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
  description = "Enable Nitro Enclaves for TEE"
  default     = true
}

variable "ebs_volume_size" {
  type        = number
  description = "EBS volume size in GB"
  default     = 500
}

variable "ssh_key_name" {
  type        = string
  description = "SSH key pair name (must exist in all 3 regions)"
}

# --- Per-region validator counts ---
variable "us_validator_count" {
  type    = number
  default = 2
}

variable "eu_validator_count" {
  type    = number
  default = 1
}

variable "ap_validator_count" {
  type    = number
  default = 1
}

# --- US East 1 ---
variable "us_vpc_id" {
  type        = string
  description = "VPC ID in us-east-1"
}

variable "us_subnet_ids" {
  type        = list(string)
  description = "Subnet IDs in us-east-1"
}

# --- EU West 1 ---
variable "eu_vpc_id" {
  type        = string
  description = "VPC ID in eu-west-1"
}

variable "eu_subnet_ids" {
  type        = list(string)
  description = "Subnet IDs in eu-west-1"
}

# --- AP Southeast 1 ---
variable "ap_vpc_id" {
  type        = string
  description = "VPC ID in ap-southeast-1"
}

variable "ap_subnet_ids" {
  type        = list(string)
  description = "Subnet IDs in ap-southeast-1"
}

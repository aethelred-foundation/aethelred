# Aethelred Validator Node Terraform Module
# Deploys validator infrastructure on AWS with TEE support

terraform {
  required_version = ">= 1.5.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

# Variables
variable "environment" {
  type        = string
  description = "Environment name (testnet, mainnet)"
}

variable "validator_count" {
  type        = number
  description = "Number of validator nodes"
  default     = 3
}

variable "instance_type" {
  type        = string
  description = "EC2 instance type for validators"
  default     = "c6i.4xlarge"  # 16 vCPU, 32 GB RAM
}

variable "nitro_instance_type" {
  type        = string
  description = "Instance type for Nitro Enclave validators"
  default     = "c6i.8xlarge"  # Supports Nitro Enclaves
}

variable "enable_nitro_enclaves" {
  type        = bool
  description = "Enable AWS Nitro Enclaves for TEE"
  default     = true
}

variable "enable_sgx" {
  type        = bool
  description = "Enable Intel SGX instances"
  default     = false
}

variable "vpc_id" {
  type        = string
  description = "VPC ID for deployment"
}

variable "subnet_ids" {
  type        = list(string)
  description = "Subnet IDs for validators (across AZs)"
}

variable "ssh_key_name" {
  type        = string
  description = "SSH key pair name"
}

variable "ebs_volume_size" {
  type        = number
  description = "EBS volume size in GB"
  default     = 500
}

variable "tags" {
  type        = map(string)
  description = "Tags to apply to resources"
  default     = {}
}

# Locals
locals {
  name_prefix = "aethelred-${var.environment}"
  common_tags = merge(var.tags, {
    Project     = "Aethelred"
    Environment = var.environment
    ManagedBy   = "Terraform"
  })
}

# Security Group for Validators
resource "aws_security_group" "validator" {
  name_prefix = "${local.name_prefix}-validator-"
  description = "Security group for Aethelred validators"
  vpc_id      = var.vpc_id

  # P2P port
  ingress {
    from_port   = 26656
    to_port     = 26656
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
    description = "P2P networking"
  }

  # RPC port (restricted)
  ingress {
    from_port   = 26657
    to_port     = 26657
    protocol    = "tcp"
    cidr_blocks = ["10.0.0.0/8"]  # Internal only
    description = "RPC endpoint"
  }

  # gRPC port (restricted)
  ingress {
    from_port   = 9090
    to_port     = 9090
    protocol    = "tcp"
    cidr_blocks = ["10.0.0.0/8"]
    description = "gRPC endpoint"
  }

  # Prometheus metrics (restricted)
  ingress {
    from_port   = 26660
    to_port     = 26660
    protocol    = "tcp"
    cidr_blocks = ["10.0.0.0/8"]
    description = "Prometheus metrics"
  }

  # SSH (restricted to bastion)
  ingress {
    from_port       = 22
    to_port         = 22
    protocol        = "tcp"
    security_groups = [aws_security_group.bastion.id]
    description     = "SSH from bastion"
  }

  # All outbound
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = merge(local.common_tags, {
    Name = "${local.name_prefix}-validator-sg"
  })

  lifecycle {
    create_before_destroy = true
  }
}

# Bastion Security Group
resource "aws_security_group" "bastion" {
  name_prefix = "${local.name_prefix}-bastion-"
  description = "Security group for bastion host"
  vpc_id      = var.vpc_id

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]  # Restrict to your IP in production
    description = "SSH access"
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = merge(local.common_tags, {
    Name = "${local.name_prefix}-bastion-sg"
  })
}

# IAM Role for Validators
resource "aws_iam_role" "validator" {
  name_prefix = "${local.name_prefix}-validator-"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "ec2.amazonaws.com"
        }
      }
    ]
  })

  tags = local.common_tags
}

# IAM Policy for Validators (S3, KMS, CloudWatch)
resource "aws_iam_role_policy" "validator" {
  name_prefix = "${local.name_prefix}-validator-"
  role        = aws_iam_role.validator.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "s3:GetObject",
          "s3:PutObject",
          "s3:ListBucket"
        ]
        Resource = [
          "arn:aws:s3:::${local.name_prefix}-state/*",
          "arn:aws:s3:::${local.name_prefix}-state"
        ]
      },
      {
        Effect = "Allow"
        Action = [
          "kms:Decrypt",
          "kms:Encrypt",
          "kms:GenerateDataKey"
        ]
        Resource = [aws_kms_key.validator.arn]
      },
      {
        Effect = "Allow"
        Action = [
          "cloudwatch:PutMetricData",
          "logs:CreateLogStream",
          "logs:PutLogEvents"
        ]
        Resource = "*"
      },
      {
        Effect = "Allow"
        Action = [
          "ssm:GetParameter",
          "ssm:GetParameters"
        ]
        Resource = "arn:aws:ssm:*:*:parameter/aethelred/${var.environment}/*"
      }
    ]
  })
}

# IAM Instance Profile
resource "aws_iam_instance_profile" "validator" {
  name_prefix = "${local.name_prefix}-validator-"
  role        = aws_iam_role.validator.name

  tags = local.common_tags
}

# KMS Key for encryption
resource "aws_kms_key" "validator" {
  description             = "KMS key for Aethelred validator encryption"
  deletion_window_in_days = 30
  enable_key_rotation     = true

  tags = merge(local.common_tags, {
    Name = "${local.name_prefix}-validator-kms"
  })
}

resource "aws_kms_alias" "validator" {
  name          = "alias/${local.name_prefix}-validator"
  target_key_id = aws_kms_key.validator.key_id
}

# Launch Template for Validators
resource "aws_launch_template" "validator" {
  name_prefix   = "${local.name_prefix}-validator-"
  image_id      = data.aws_ami.validator.id
  instance_type = var.enable_nitro_enclaves ? var.nitro_instance_type : var.instance_type
  key_name      = var.ssh_key_name

  iam_instance_profile {
    arn = aws_iam_instance_profile.validator.arn
  }

  network_interfaces {
    associate_public_ip_address = false
    security_groups             = [aws_security_group.validator.id]
    delete_on_termination       = true
  }

  block_device_mappings {
    device_name = "/dev/xvda"
    ebs {
      volume_size           = var.ebs_volume_size
      volume_type           = "gp3"
      iops                  = 10000
      throughput            = 500
      encrypted             = true
      kms_key_id            = aws_kms_key.validator.arn
      delete_on_termination = false
    }
  }

  # Enable Nitro Enclaves if configured
  dynamic "enclave_options" {
    for_each = var.enable_nitro_enclaves ? [1] : []
    content {
      enabled = true
    }
  }

  monitoring {
    enabled = true
  }

  metadata_options {
    http_endpoint               = "enabled"
    http_tokens                 = "required"
    http_put_response_hop_limit = 1
  }

  user_data = base64encode(templatefile("${path.module}/userdata.sh.tpl", {
    environment      = var.environment
    chain_id         = "aethelred-${var.environment}-1"
    enable_nitro     = var.enable_nitro_enclaves
  }))

  tag_specifications {
    resource_type = "instance"
    tags = merge(local.common_tags, {
      Name = "${local.name_prefix}-validator"
    })
  }

  tag_specifications {
    resource_type = "volume"
    tags = merge(local.common_tags, {
      Name = "${local.name_prefix}-validator-volume"
    })
  }

  tags = local.common_tags

  lifecycle {
    create_before_destroy = true
  }
}

# Auto Scaling Group for Validators
resource "aws_autoscaling_group" "validator" {
  name_prefix         = "${local.name_prefix}-validator-"
  min_size            = var.validator_count
  max_size            = var.validator_count
  desired_capacity    = var.validator_count
  vpc_zone_identifier = var.subnet_ids

  launch_template {
    id      = aws_launch_template.validator.id
    version = "$Latest"
  }

  health_check_type         = "EC2"
  health_check_grace_period = 300

  dynamic "tag" {
    for_each = merge(local.common_tags, {
      Name = "${local.name_prefix}-validator"
    })
    content {
      key                 = tag.key
      value               = tag.value
      propagate_at_launch = true
    }
  }

  lifecycle {
    ignore_changes = [desired_capacity]
  }
}

# Data source for validator AMI
data "aws_ami" "validator" {
  most_recent = true
  owners      = ["self"]

  filter {
    name   = "name"
    values = ["aethelred-validator-*"]
  }

  filter {
    name   = "virtualization-type"
    values = ["hvm"]
  }
}

# S3 Bucket for state storage
resource "aws_s3_bucket" "state" {
  bucket = "${local.name_prefix}-state"

  tags = merge(local.common_tags, {
    Name = "${local.name_prefix}-state"
  })
}

resource "aws_s3_bucket_versioning" "state" {
  bucket = aws_s3_bucket.state.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "state" {
  bucket = aws_s3_bucket.state.id

  rule {
    apply_server_side_encryption_by_default {
      kms_master_key_id = aws_kms_key.validator.arn
      sse_algorithm     = "aws:kms"
    }
  }
}

resource "aws_s3_bucket_public_access_block" "state" {
  bucket = aws_s3_bucket.state.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# CloudWatch Log Group
resource "aws_cloudwatch_log_group" "validator" {
  name              = "/aethelred/${var.environment}/validator"
  retention_in_days = 30
  kms_key_id        = aws_kms_key.validator.arn

  tags = local.common_tags
}

# Outputs
output "security_group_id" {
  description = "Security group ID for validators"
  value       = aws_security_group.validator.id
}

output "iam_role_arn" {
  description = "IAM role ARN for validators"
  value       = aws_iam_role.validator.arn
}

output "kms_key_id" {
  description = "KMS key ID for encryption"
  value       = aws_kms_key.validator.id
}

output "s3_bucket_name" {
  description = "S3 bucket name for state storage"
  value       = aws_s3_bucket.state.bucket
}

output "autoscaling_group_name" {
  description = "Auto Scaling Group name"
  value       = aws_autoscaling_group.validator.name
}

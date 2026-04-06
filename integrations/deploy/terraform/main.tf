# =============================================================================
# Aethelred 100-Node Stress Test Infrastructure
# =============================================================================
#
# This Terraform configuration deploys a 100-node test cluster for Aethelred
# blockchain stress testing prior to mainnet launch.
#
# Architecture:
#   - 50 Validator Nodes (compute-optimized)
#   - 50 Full Nodes (general purpose)
#   - 5 Load Generator (Spammer) Nodes
#   - 1 Monitoring Stack (Prometheus + Grafana)
#
# Usage:
#   terraform init
#   terraform plan -out=plan.tfplan
#   terraform apply plan.tfplan
#
# Cost Estimate: ~$2,500/day for full cluster
#
# =============================================================================

terraform {
  required_version = ">= 1.5.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }

  backend "s3" {
    bucket         = "aethelred-terraform-state"
    key            = "stress-test/terraform.tfstate"
    region         = "me-central-1"
    encrypt        = true
    dynamodb_table = "aethelred-terraform-locks"
  }
}

# =============================================================================
# Provider Configuration
# =============================================================================

provider "aws" {
  region = var.aws_region

  default_tags {
    tags = {
      Project     = "Aethelred"
      Environment = var.environment
      Terraform   = "true"
      ManagedBy   = "infrastructure-team"
    }
  }
}

# =============================================================================
# Variables
# =============================================================================

variable "aws_region" {
  description = "AWS region for deployment"
  type        = string
  default     = "me-central-1" # UAE Region (simulating FAB latency)
}

variable "environment" {
  description = "Environment name (stress-test, staging, production)"
  type        = string
  default     = "stress-test"
}

variable "validator_count" {
  description = "Number of validator nodes"
  type        = number
  default     = 50
}

variable "full_node_count" {
  description = "Number of full nodes"
  type        = number
  default     = 50
}

variable "spammer_count" {
  description = "Number of load generator nodes"
  type        = number
  default     = 5
}

variable "spammer_rate" {
  description = "Transactions per second per spammer"
  type        = number
  default     = 2000
}

variable "validator_instance_type" {
  description = "EC2 instance type for validators"
  type        = string
  default     = "c6a.2xlarge" # AMD EPYC, 8 vCPU, 16GB RAM
}

variable "full_node_instance_type" {
  description = "EC2 instance type for full nodes"
  type        = string
  default     = "c6a.xlarge" # AMD EPYC, 4 vCPU, 8GB RAM
}

variable "spammer_instance_type" {
  description = "EC2 instance type for load generators"
  type        = string
  default     = "c6a.8xlarge" # AMD EPYC, 32 vCPU, 64GB RAM
}

variable "aethelred_docker_image" {
  description = "Docker image for Aethelred node"
  type        = string
  default     = "ghcr.io/aethelred-foundation/aethelred/aethelredd:latest"
}

variable "ssh_key_name" {
  description = "SSH key pair name for EC2 access"
  type        = string
  default     = "aethelred-stress-test"
}

variable "vpc_cidr" {
  description = "CIDR block for VPC"
  type        = string
  default     = "10.0.0.0/16"
}

# =============================================================================
# Data Sources
# =============================================================================

data "aws_ami" "ubuntu" {
  most_recent = true
  owners      = ["099720109477"] # Canonical

  filter {
    name   = "name"
    values = ["ubuntu/images/hvm-ssd/ubuntu-jammy-22.04-amd64-server-*"]
  }

  filter {
    name   = "virtualization-type"
    values = ["hvm"]
  }
}

data "aws_availability_zones" "available" {
  state = "available"
}

# =============================================================================
# VPC Configuration
# =============================================================================

resource "aws_vpc" "main" {
  cidr_block           = var.vpc_cidr
  enable_dns_hostnames = true
  enable_dns_support   = true

  tags = {
    Name = "aethelred-${var.environment}-vpc"
  }
}

resource "aws_internet_gateway" "main" {
  vpc_id = aws_vpc.main.id

  tags = {
    Name = "aethelred-${var.environment}-igw"
  }
}

resource "aws_subnet" "public" {
  count                   = 3
  vpc_id                  = aws_vpc.main.id
  cidr_block              = cidrsubnet(var.vpc_cidr, 4, count.index)
  availability_zone       = data.aws_availability_zones.available.names[count.index % length(data.aws_availability_zones.available.names)]
  map_public_ip_on_launch = true

  tags = {
    Name = "aethelred-${var.environment}-public-${count.index}"
  }
}

resource "aws_route_table" "public" {
  vpc_id = aws_vpc.main.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.main.id
  }

  tags = {
    Name = "aethelred-${var.environment}-public-rt"
  }
}

resource "aws_route_table_association" "public" {
  count          = length(aws_subnet.public)
  subnet_id      = aws_subnet.public[count.index].id
  route_table_id = aws_route_table.public.id
}

# =============================================================================
# Security Groups
# =============================================================================

resource "aws_security_group" "validator" {
  name        = "aethelred-${var.environment}-validator-sg"
  description = "Security group for Aethelred validator nodes"
  vpc_id      = aws_vpc.main.id

  # P2P Communication
  ingress {
    from_port   = 26656
    to_port     = 26656
    protocol    = "tcp"
    cidr_blocks = [var.vpc_cidr]
    description = "CometBFT P2P"
  }

  # Consensus RPC (internal only)
  ingress {
    from_port   = 26657
    to_port     = 26657
    protocol    = "tcp"
    cidr_blocks = [var.vpc_cidr]
    description = "CometBFT RPC"
  }

  # gRPC
  ingress {
    from_port   = 9090
    to_port     = 9090
    protocol    = "tcp"
    cidr_blocks = [var.vpc_cidr]
    description = "gRPC"
  }

  # Prometheus metrics
  ingress {
    from_port   = 26660
    to_port     = 26660
    protocol    = "tcp"
    cidr_blocks = [var.vpc_cidr]
    description = "Prometheus metrics"
  }

  # SSH (from bastion only in production)
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
    description = "SSH access"
  }

  # All outbound
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "aethelred-${var.environment}-validator-sg"
  }
}

resource "aws_security_group" "spammer" {
  name        = "aethelred-${var.environment}-spammer-sg"
  description = "Security group for load generator nodes"
  vpc_id      = aws_vpc.main.id

  # SSH
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
    description = "SSH access"
  }

  # Prometheus metrics
  ingress {
    from_port   = 9100
    to_port     = 9100
    protocol    = "tcp"
    cidr_blocks = [var.vpc_cidr]
    description = "Node exporter metrics"
  }

  # All outbound
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "aethelred-${var.environment}-spammer-sg"
  }
}

resource "aws_security_group" "monitoring" {
  name        = "aethelred-${var.environment}-monitoring-sg"
  description = "Security group for monitoring stack"
  vpc_id      = aws_vpc.main.id

  # Grafana
  ingress {
    from_port   = 3000
    to_port     = 3000
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
    description = "Grafana dashboard"
  }

  # Prometheus
  ingress {
    from_port   = 9090
    to_port     = 9090
    protocol    = "tcp"
    cidr_blocks = [var.vpc_cidr]
    description = "Prometheus"
  }

  # SSH
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  # All outbound
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "aethelred-${var.environment}-monitoring-sg"
  }
}

# =============================================================================
# IAM Role for EC2 Instances
# =============================================================================

resource "aws_iam_role" "validator" {
  name = "aethelred-${var.environment}-validator-role"

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
}

resource "aws_iam_role_policy" "validator" {
  name = "aethelred-${var.environment}-validator-policy"
  role = aws_iam_role.validator.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "logs:CreateLogGroup",
          "logs:CreateLogStream",
          "logs:PutLogEvents",
          "logs:DescribeLogStreams"
        ]
        Resource = "arn:aws:logs:*:*:*"
      },
      {
        Effect = "Allow"
        Action = [
          "ssm:GetParameter",
          "ssm:GetParameters",
          "ssm:GetParametersByPath"
        ]
        Resource = "arn:aws:ssm:*:*:parameter/aethelred/*"
      },
      {
        Effect = "Allow"
        Action = [
          "ecr:GetAuthorizationToken",
          "ecr:BatchCheckLayerAvailability",
          "ecr:GetDownloadUrlForLayer",
          "ecr:BatchGetImage"
        ]
        Resource = "*"
      }
    ]
  })
}

resource "aws_iam_instance_profile" "validator" {
  name = "aethelred-${var.environment}-validator-profile"
  role = aws_iam_role.validator.name
}

# =============================================================================
# Validator Nodes (50 nodes)
# =============================================================================

resource "aws_instance" "validator" {
  count         = var.validator_count
  ami           = data.aws_ami.ubuntu.id
  instance_type = var.validator_instance_type
  key_name      = var.ssh_key_name
  subnet_id     = aws_subnet.public[count.index % length(aws_subnet.public)].id

  vpc_security_group_ids = [aws_security_group.validator.id]
  iam_instance_profile   = aws_iam_instance_profile.validator.name

  root_block_device {
    volume_size = 200
    volume_type = "gp3"
    iops        = 3000
    throughput  = 250
    encrypted   = true
  }

  user_data = base64encode(<<-EOF
    #!/bin/bash
    set -e

    # Update system
    apt-get update && apt-get upgrade -y

    # Install Docker
    curl -fsSL https://get.docker.com | sh
    systemctl enable docker
    systemctl start docker

    # Install monitoring agent
    wget https://github.com/prometheus/node_exporter/releases/download/v1.6.1/node_exporter-1.6.1.linux-amd64.tar.gz
    tar xvfz node_exporter-1.6.1.linux-amd64.tar.gz
    cp node_exporter-1.6.1.linux-amd64/node_exporter /usr/local/bin/

    # Create systemd service for node exporter
    cat > /etc/systemd/system/node_exporter.service << 'NODEEXP'
    [Unit]
    Description=Node Exporter
    After=network.target

    [Service]
    User=nobody
    ExecStart=/usr/local/bin/node_exporter

    [Install]
    WantedBy=multi-user.target
    NODEEXP

    systemctl daemon-reload
    systemctl enable node_exporter
    systemctl start node_exporter

    # Generate validator ID from instance index
    VALIDATOR_ID=${count.index}

    # Create node data directory
    mkdir -p /data/aethelred

    # Run Aethelred validator node
    docker run -d \
      --name aethelred-validator \
      --restart unless-stopped \
      --net=host \
      -v /data/aethelred:/data \
      -e ROLE=validator \
      -e VALIDATOR_ID=$VALIDATOR_ID \
      -e PEER_COUNT=${var.validator_count + var.full_node_count} \
      -e GENESIS_TIME=$(date -u +%Y-%m-%dT%H:%M:%SZ) \
      ${var.aethelred_docker_image}

    # Wait for node to start
    sleep 30

    echo "Validator $VALIDATOR_ID started successfully" | logger -t aethelred
  EOF
  )

  tags = {
    Name = "Aethelred-Validator-${count.index}"
    Role = "validator"
    Index = count.index
  }

  lifecycle {
    create_before_destroy = true
  }
}

# =============================================================================
# Full Nodes (50 nodes)
# =============================================================================

resource "aws_instance" "full_node" {
  count         = var.full_node_count
  ami           = data.aws_ami.ubuntu.id
  instance_type = var.full_node_instance_type
  key_name      = var.ssh_key_name
  subnet_id     = aws_subnet.public[count.index % length(aws_subnet.public)].id

  vpc_security_group_ids = [aws_security_group.validator.id]
  iam_instance_profile   = aws_iam_instance_profile.validator.name

  root_block_device {
    volume_size = 100
    volume_type = "gp3"
    encrypted   = true
  }

  user_data = base64encode(<<-EOF
    #!/bin/bash
    set -e

    apt-get update && apt-get upgrade -y
    curl -fsSL https://get.docker.com | sh
    systemctl enable docker && systemctl start docker

    mkdir -p /data/aethelred

    # Run Aethelred full node
    docker run -d \
      --name aethelred-fullnode \
      --restart unless-stopped \
      --net=host \
      -v /data/aethelred:/data \
      -e ROLE=fullnode \
      -e SEED_NODES=${join(",", [for i, v in aws_instance.validator : v.private_ip])} \
      ${var.aethelred_docker_image}
  EOF
  )

  tags = {
    Name = "Aethelred-FullNode-${count.index}"
    Role = "fullnode"
    Index = count.index
  }

  depends_on = [aws_instance.validator]
}

# =============================================================================
# Load Generator (Spammer) Nodes
# =============================================================================

resource "aws_instance" "spammer" {
  count         = var.spammer_count
  ami           = data.aws_ami.ubuntu.id
  instance_type = var.spammer_instance_type
  key_name      = var.ssh_key_name
  subnet_id     = aws_subnet.public[count.index % length(aws_subnet.public)].id

  vpc_security_group_ids = [aws_security_group.spammer.id]
  iam_instance_profile   = aws_iam_instance_profile.validator.name

  root_block_device {
    volume_size = 50
    volume_type = "gp3"
    encrypted   = true
  }

  user_data = base64encode(<<-EOF
    #!/bin/bash
    set -e

    apt-get update && apt-get upgrade -y
    curl -fsSL https://get.docker.com | sh
    systemctl enable docker && systemctl start docker

    # Wait for validators to be ready
    sleep 120

    # Target validator for this spammer
    TARGET_VALIDATOR=${aws_instance.validator[count.index % var.validator_count].private_ip}

    # Run the spammer/load generator
    docker run -d \
      --name aethelred-spammer \
      --restart unless-stopped \
      --net=host \
      -e TARGET=$TARGET_VALIDATOR \
      -e RATE=${var.spammer_rate} \
      -e DURATION=3600 \
      ${var.aethelred_docker_image}-spammer

    # Alternative: Use the CLI spammer tool
    # docker run -d --net=host aethelred/cli:latest \
    #   spammer --target $TARGET_VALIDATOR --rate ${var.spammer_rate}

    echo "Spammer ${count.index} started targeting $TARGET_VALIDATOR at ${var.spammer_rate} tx/sec" | logger -t aethelred
  EOF
  )

  tags = {
    Name = "Aethelred-Spammer-${count.index}"
    Role = "spammer"
    Index = count.index
    TargetRate = var.spammer_rate
  }

  depends_on = [aws_instance.validator]
}

# =============================================================================
# Monitoring Stack
# =============================================================================

resource "aws_instance" "monitoring" {
  ami           = data.aws_ami.ubuntu.id
  instance_type = "t3.xlarge"
  key_name      = var.ssh_key_name
  subnet_id     = aws_subnet.public[0].id

  vpc_security_group_ids = [aws_security_group.monitoring.id]
  iam_instance_profile   = aws_iam_instance_profile.validator.name

  root_block_device {
    volume_size = 500
    volume_type = "gp3"
    encrypted   = true
  }

  user_data = base64encode(<<-EOF
    #!/bin/bash
    set -e

    apt-get update && apt-get upgrade -y
    curl -fsSL https://get.docker.com | sh
    systemctl enable docker && systemctl start docker

    # Install Docker Compose
    curl -L "https://github.com/docker/compose/releases/download/v2.23.0/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose
    chmod +x /usr/local/bin/docker-compose

    mkdir -p /opt/monitoring
    cd /opt/monitoring

    # Create Prometheus config
    cat > prometheus.yml << 'PROMCONFIG'
    global:
      scrape_interval: 15s
      evaluation_interval: 15s

    scrape_configs:
      - job_name: 'validators'
        static_configs:
          - targets:
    ${join("\n", formatlist("          - '%s:26660'", [for v in aws_instance.validator : v.private_ip]))}

      - job_name: 'fullnodes'
        static_configs:
          - targets:
    ${join("\n", formatlist("          - '%s:26660'", [for f in aws_instance.full_node : f.private_ip]))}

      - job_name: 'node_exporter'
        static_configs:
          - targets:
    ${join("\n", formatlist("          - '%s:9100'", concat([for v in aws_instance.validator : v.private_ip], [for f in aws_instance.full_node : f.private_ip])))}
    PROMCONFIG

    # Create docker-compose file
    cat > docker-compose.yml << 'COMPOSE'
    version: '3.8'

    services:
      prometheus:
        image: prom/prometheus:latest
        container_name: prometheus
        restart: unless-stopped
        volumes:
          - ./prometheus.yml:/etc/prometheus/prometheus.yml
          - prometheus_data:/prometheus
        ports:
          - "9090:9090"
        command:
          - '--config.file=/etc/prometheus/prometheus.yml'
          - '--storage.tsdb.path=/prometheus'
          - '--storage.tsdb.retention.time=30d'

      grafana:
        image: grafana/grafana:latest
        container_name: grafana
        restart: unless-stopped
        volumes:
          - grafana_data:/var/lib/grafana
        ports:
          - "3000:3000"
        environment:
          - GF_SECURITY_ADMIN_PASSWORD=aethelred-stress-test
          - GF_USERS_ALLOW_SIGN_UP=false

      alertmanager:
        image: prom/alertmanager:latest
        container_name: alertmanager
        restart: unless-stopped
        ports:
          - "9093:9093"

    volumes:
      prometheus_data:
      grafana_data:
    COMPOSE

    docker-compose up -d

    echo "Monitoring stack started" | logger -t aethelred
  EOF
  )

  tags = {
    Name = "Aethelred-Monitoring"
    Role = "monitoring"
  }

  depends_on = [aws_instance.validator, aws_instance.full_node]
}

# =============================================================================
# Outputs
# =============================================================================

output "validator_ips" {
  description = "Private IPs of validator nodes"
  value       = aws_instance.validator[*].private_ip
}

output "validator_public_ips" {
  description = "Public IPs of validator nodes"
  value       = aws_instance.validator[*].public_ip
}

output "full_node_ips" {
  description = "Private IPs of full nodes"
  value       = aws_instance.full_node[*].private_ip
}

output "spammer_ips" {
  description = "Private IPs of spammer nodes"
  value       = aws_instance.spammer[*].private_ip
}

output "monitoring_url" {
  description = "URL for Grafana dashboard"
  value       = "http://${aws_instance.monitoring.public_ip}:3000"
}

output "prometheus_url" {
  description = "URL for Prometheus"
  value       = "http://${aws_instance.monitoring.public_ip}:9090"
}

output "total_target_tps" {
  description = "Total target transactions per second"
  value       = var.spammer_count * var.spammer_rate
}

output "ssh_command_example" {
  description = "SSH command to connect to first validator"
  value       = "ssh -i ~/.ssh/${var.ssh_key_name}.pem ubuntu@${aws_instance.validator[0].public_ip}"
}

#!/bin/bash
set -euo pipefail

# Aethelred Validator Node Bootstrap Script
# This script initializes a validator node on first boot

ENVIRONMENT="${environment}"
CHAIN_ID="${chain_id}"
ENABLE_NITRO="${enable_nitro}"

LOG_FILE="/var/log/aethelred-bootstrap.log"
exec > >(tee -a $LOG_FILE) 2>&1

echo "$(date '+%Y-%m-%d %H:%M:%S') Starting Aethelred validator bootstrap..."

# Install dependencies
apt-get update
apt-get install -y \
    awscli \
    jq \
    docker.io \
    docker-compose \
    prometheus-node-exporter

# Enable Docker
systemctl enable docker
systemctl start docker

# Create aethelred user
useradd -m -s /bin/bash aethelred || true
usermod -aG docker aethelred

# Set up directories
mkdir -p /opt/aethelred/{bin,config,data,logs}
chown -R aethelred:aethelred /opt/aethelred

# Download validator binary from S3
aws s3 cp s3://aethelred-releases/$ENVIRONMENT/aethelredd /opt/aethelred/bin/aethelredd
chmod +x /opt/aethelred/bin/aethelredd

# Get node configuration from Parameter Store
aws ssm get-parameter --name "/aethelred/$ENVIRONMENT/genesis" --output text --query Parameter.Value > /opt/aethelred/config/genesis.json
aws ssm get-parameter --name "/aethelred/$ENVIRONMENT/config" --output text --query Parameter.Value > /opt/aethelred/config/config.toml
aws ssm get-parameter --name "/aethelred/$ENVIRONMENT/app-config" --output text --query Parameter.Value > /opt/aethelred/config/app.toml

# Get validator keys from Secrets Manager (only for active validators)
INSTANCE_ID=$(curl -s http://169.254.169.254/latest/meta-data/instance-id)
VALIDATOR_KEYS=$(aws secretsmanager get-secret-value --secret-id "aethelred/$ENVIRONMENT/validator-keys/$INSTANCE_ID" --query SecretString --output text 2>/dev/null || echo "")

if [ -n "$VALIDATOR_KEYS" ]; then
    echo "$VALIDATOR_KEYS" | jq -r '.priv_validator_key' > /opt/aethelred/config/priv_validator_key.json
    echo "$VALIDATOR_KEYS" | jq -r '.node_key' > /opt/aethelred/config/node_key.json
    chmod 600 /opt/aethelred/config/priv_validator_key.json
    chmod 600 /opt/aethelred/config/node_key.json
fi

# Initialize node if not already done
if [ ! -f /opt/aethelred/data/priv_validator_state.json ]; then
    sudo -u aethelred /opt/aethelred/bin/aethelredd init validator --chain-id $CHAIN_ID --home /opt/aethelred
fi

# Set up Nitro Enclaves if enabled
if [ "$ENABLE_NITRO" = "true" ]; then
    echo "Setting up AWS Nitro Enclaves..."

    # Install Nitro Enclaves CLI
    amazon-linux-extras install aws-nitro-enclaves-cli -y 2>/dev/null || \
    apt-get install -y aws-nitro-enclaves-cli aws-nitro-enclaves-cli-devel 2>/dev/null || true

    # Configure enclave allocator
    cat > /etc/nitro_enclaves/allocator.yaml <<EOF
---
memory_mib: 4096
cpu_count: 2
EOF

    # Start enclave allocator
    systemctl enable nitro-enclaves-allocator
    systemctl start nitro-enclaves-allocator

    # Add aethelred user to ne group
    usermod -aG ne aethelred
fi

# Create systemd service
cat > /etc/systemd/system/aethelred.service <<EOF
[Unit]
Description=Aethelred Validator Node
After=network.target docker.service
Wants=docker.service

[Service]
Type=simple
User=aethelred
Group=aethelred
WorkingDirectory=/opt/aethelred
ExecStart=/opt/aethelred/bin/aethelredd start \
    --home /opt/aethelred \
    --log_level info \
    --log_format json
Restart=always
RestartSec=5
LimitNOFILE=65536
StandardOutput=append:/opt/aethelred/logs/validator.log
StandardError=append:/opt/aethelred/logs/validator-error.log

[Install]
WantedBy=multi-user.target
EOF

# Set up log rotation
cat > /etc/logrotate.d/aethelred <<EOF
/opt/aethelred/logs/*.log {
    daily
    rotate 14
    compress
    delaycompress
    missingok
    notifempty
    create 0640 aethelred aethelred
    sharedscripts
    postrotate
        systemctl reload aethelred 2>/dev/null || true
    endscript
}
EOF

# Configure CloudWatch agent
cat > /opt/aws/amazon-cloudwatch-agent/etc/amazon-cloudwatch-agent.json <<EOF
{
    "agent": {
        "metrics_collection_interval": 60,
        "run_as_user": "cwagent"
    },
    "logs": {
        "logs_collected": {
            "files": {
                "collect_list": [
                    {
                        "file_path": "/opt/aethelred/logs/validator.log",
                        "log_group_name": "/aethelred/$ENVIRONMENT/validator",
                        "log_stream_name": "{instance_id}/validator",
                        "timezone": "UTC"
                    },
                    {
                        "file_path": "/opt/aethelred/logs/validator-error.log",
                        "log_group_name": "/aethelred/$ENVIRONMENT/validator",
                        "log_stream_name": "{instance_id}/validator-error",
                        "timezone": "UTC"
                    }
                ]
            }
        }
    },
    "metrics": {
        "namespace": "Aethelred/$ENVIRONMENT",
        "metrics_collected": {
            "cpu": {
                "measurement": ["cpu_usage_idle", "cpu_usage_user", "cpu_usage_system"],
                "metrics_collection_interval": 60
            },
            "disk": {
                "measurement": ["used_percent"],
                "metrics_collection_interval": 60,
                "resources": ["/"]
            },
            "mem": {
                "measurement": ["mem_used_percent"],
                "metrics_collection_interval": 60
            }
        }
    }
}
EOF

# Start CloudWatch agent
amazon-cloudwatch-agent-ctl -a fetch-config -m ec2 -c file:/opt/aws/amazon-cloudwatch-agent/etc/amazon-cloudwatch-agent.json -s 2>/dev/null || true

# Enable and start the validator service
systemctl daemon-reload
systemctl enable aethelred
systemctl start aethelred

echo "$(date '+%Y-%m-%d %H:%M:%S') Aethelred validator bootstrap complete!"

# Signal successful completion
/opt/aws/bin/cfn-signal -e $? --stack $ENVIRONMENT --resource ValidatorASG --region $(curl -s http://169.254.169.254/latest/meta-data/placement/region) 2>/dev/null || true

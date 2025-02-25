# Security Scanner Infrastructure

This module deploys a security scanning infrastructure on AWS that runs CodeQL analysis on GitHub repositories.

## Quick Start

1. Initialize and apply the Terraform configuration:
```bash
terraform init
terraform apply
```

2. Get the connection details:
```bash
./modules/security_scanner/connect.sh
```

## API Usage

The security scanner exposes a REST API endpoint for running CodeQL analysis.

### Run Analysis

**Endpoint:** `POST http://<instance-ip>:5000/analyze`

```
curl -X POST http://localhost:5000/analyze \
  -H 'Content-Type: application/json' \
  -d '{"github_url": "https://github.com/juice-shop/juice-shop"}'

```

**Request Body:**
```json
{
    "github_url": "https://github.com/username/repository"
}
```

**Response:**
```json
{
    "repository": "https://github.com/username/repository",
    "detected_languages": ["python", "javascript"],
    "analysis_results": {
        "results": [
            {
                "ruleId": "rule-id",
                "message": {
                    "text": "Security issue description"
                },
                "locations": [...]
            }
        ],
        "saved_analysis_files": [
            "/data/results_python_abc123.sarif",
            "/data/results_javascript_def456.sarif"
        ]
    }
}
```

### Health Check

**Endpoint:** `GET http://<instance-ip>:5000/health`

**Response:**
```json
{
    "status": "healthy"
}
```

## Features

- Automatic language detection
- Multi-language analysis support
- SARIF output format
- Persistent storage of analysis results
- Secure SSH access
- AWS Systems Manager integration

## Security Considerations

- By default, the security groups allow access from anywhere (0.0.0.0/0). For production use, restrict access using the `allowed_*_cidr_blocks` variables.
- SSH keys are stored in AWS Secrets Manager
- IMDSv2 is enforced
- Root volumes are encrypted

## Infrastructure Components

- EC2 instance (t2.2xlarge)
- VPC with public/private subnets
- Security groups
- IAM roles and policies
- AWS Secrets Manager for SSH keys

## Variables

Key variables that can be customized:

| Name | Description | Default |
|------|-------------|---------|
| aws_region | AWS region | us-west-1 |
| environment | Environment name | dev |
| vpc_cidr | VPC CIDR block | 10.0.0.0/16 |
| allowed_ssh_cidr_blocks | Allowed SSH CIDR blocks | ["0.0.0.0/0"] |
| allowed_http_cidr_blocks | Allowed HTTP CIDR blocks | ["0.0.0.0/0"] |
| allowed_https_cidr_blocks | Allowed HTTPS CIDR blocks | ["0.0.0.0/0"] | 
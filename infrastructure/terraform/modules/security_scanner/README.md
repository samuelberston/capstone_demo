# Security Scanner Module

This Terraform module deploys a security scanning server on AWS EC2, configured with:
- CodeQL for code analysis
- OWASP Dependency Check for dependency scanning
- Jenkins integration support

## Features

- Deploys an EC2 instance with CodeQL CLI pre-installed
- Creates necessary security groups for SSH and HTTP/HTTPS access
- Sets up IAM roles and policies for AWS Systems Manager access
- Automatically installs and configures CodeQL on instance startup
- Stores instance information in SSM Parameter Store

## Requirements

- Terraform >= 1.0
- AWS provider
- An existing VPC and subnet
- An SSH key pair in AWS

## Usage

```hcl
hcl
module "codeql" {
source = "./modules/codeql"
vpc_id = "vpc-xxxxx"
subnet_id = "subnet-xxxxx"
environment = "dev"
key_name = "your-key-name"
allowed_ssh_cidr_blocks = ["10.0.0.0/16"]
allowed_http_cidr_blocks = ["10.0.0.0/16"]
allowed_https_cidr_blocks = ["10.0.0.0/16"]
tags = {
Environment = "dev"
Project = "security-scanning"
}
}
```


## Inputs

| Name | Description | Type | Default | Required |
|------|-------------|------|---------|----------|
| vpc_id | ID of the VPC to use | string | - | yes |
| subnet_id | ID of the subnet to use | string | - | yes |
| environment | Environment name (e.g., dev, prod) | string | - | yes |
| key_name | Name of the SSH key pair | string | - | yes |
| instance_type | EC2 instance type | string | "t2.2xlarge" | no |
| volume_size | Size of the root volume in GB | number | 32 | no |
| allowed_ssh_cidr_blocks | List of CIDR blocks allowed for SSH | list(string) | ["0.0.0.0/0"] | no |
| allowed_http_cidr_blocks | List of CIDR blocks allowed for HTTP | list(string) | ["0.0.0.0/0"] | no |
| allowed_https_cidr_blocks | List of CIDR blocks allowed for HTTPS | list(string) | ["0.0.0.0/0"] | no |

## Outputs

| Name | Description |
|------|-------------|
| instance_id | ID of the CodeQL EC2 instance |
| public_ip | Public IP address of the CodeQL instance |
| security_group_id | ID of the CodeQL security group |
| iam_role_arn | ARN of the CodeQL IAM role |

## Security Considerations

- By default, the security group allows access from anywhere (0.0.0.0/0). For production environments, restrict this to specific IP ranges.
- The instance uses IMDSv2 for enhanced security.
- Root volume is encrypted by default.


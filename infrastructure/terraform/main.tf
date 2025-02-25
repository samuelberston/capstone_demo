provider "aws" {
  region = var.aws_region
}

provider "tls" {}

provider "random" {}

# Create the VPC
module "vpc" {
  source = "terraform-aws-modules/vpc/aws"
  
  name = "security-scanner-vpc-${var.environment}"
  cidr = var.vpc_cidr

  azs             = var.availability_zones
  private_subnets = var.private_subnets
  public_subnets  = var.public_subnets

  enable_nat_gateway = true
  enable_vpn_gateway = false

  tags = {
    Environment = var.environment
    Project     = "security-scanning"
  }
}

# Create SSH key pair for security scanner
resource "tls_private_key" "security_scanner_key" {
  algorithm = "RSA"
  rsa_bits  = 4096
}

# Generate random suffix for the secret name
resource "random_id" "secret_suffix" {
  byte_length = 4
}

# Store the private key in Secrets Manager
resource "aws_secretsmanager_secret" "security_scanner_key" {
  name        = "security-scanner-ssh-key-${var.environment}-${random_id.secret_suffix.hex}"
  description = "SSH private key for security scanner instance"
  
  tags = {
    Environment = var.environment
    Project     = "security-scanning"
    Terraform   = "true"
  }

  lifecycle {
    create_before_destroy = true
  }
}

resource "aws_secretsmanager_secret_version" "security_scanner_key" {
  secret_id = aws_secretsmanager_secret.security_scanner_key.id
  secret_string = jsonencode({
    private_key = tls_private_key.security_scanner_key.private_key_pem
    public_key  = tls_private_key.security_scanner_key.public_key_pem
  })
}

# Create AWS key pair
resource "aws_key_pair" "security_scanner_key" {
  key_name   = "security-scanner-key-${var.environment}-${random_id.secret_suffix.hex}"
  public_key = tls_private_key.security_scanner_key.public_key_openssh
  
  tags = {
    Environment = var.environment
    Project     = "security-scanning"
    Terraform   = "true"
  }

  lifecycle {
    create_before_destroy = true
  }
}

# Create the security scanner instance
module "security_scanner" {
  source = "./modules/security_scanner"

  vpc_id                    = module.vpc.vpc_id
  subnet_id                 = module.vpc.public_subnets[0]
  environment              = var.environment
  key_name                 = aws_key_pair.security_scanner_key.key_name
  allowed_ssh_cidr_blocks  = var.allowed_ssh_cidr_blocks
  allowed_http_cidr_blocks = var.allowed_http_cidr_blocks
  allowed_https_cidr_blocks = var.allowed_https_cidr_blocks
  volume_size              = 64  # 64GB storage
  tags = {
    Environment = var.environment
    Project     = "security-scanning"
  }
}

# Output the secret name for easy retrieval
output "ssh_key_secret_name" {
  description = "Name of the AWS Secrets Manager secret containing the SSH key"
  value       = aws_secretsmanager_secret.security_scanner_key.name
}

# Output the instance public IP
output "instance_public_ip" {
  description = "Public IP address of the security scanner instance"
  value       = module.security_scanner.instance_elastic_ip
}
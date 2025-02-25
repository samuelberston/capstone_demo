variable "aws_region" {
  description = "AWS region"
  type        = string
  default     = "us-west-1"
}

variable "instance_type" {
  description = "EC2 instance type"
  type        = string
  default     = "t2.2xlarge"
}

variable "environment" {
  description = "Environment name (e.g., dev, prod)"
  type        = string
}

variable "key_name" {
  description = "Name of the SSH key pair"
  type        = string
}

variable "volume_size" {
  description = "Size of the root volume in GB"
  type        = number
  default     = 32
}

variable "vpc_id" {
  description = "ID of the VPC to use"
  type        = string
}

variable "subnet_id" {
  description = "ID of the subnet to use"
  type        = string
}

variable "tags" {
  description = "Additional tags for resources"
  type        = map(string)
  default     = {}
}

variable "allowed_ssh_cidr_blocks" {
  description = "List of CIDR blocks allowed to connect via SSH"
  type        = list(string)
  default     = ["0.0.0.0/0"]  # Warning: This allows access from anywhere, consider restricting in production
}

variable "allowed_http_cidr_blocks" {
  description = "List of CIDR blocks allowed to connect via HTTP"
  type        = list(string)
  default     = ["0.0.0.0/0"]  # Warning: This allows access from anywhere, consider restricting in production
}

variable "allowed_https_cidr_blocks" {
  description = "List of CIDR blocks allowed to connect via HTTPS"
  type        = list(string)
  default     = ["0.0.0.0/0"]  # Warning: This allows access from anywhere, consider restricting in production
}

variable "app_port" {
  description = "Port for the Flask application"
  type        = number
  default     = 5000
}
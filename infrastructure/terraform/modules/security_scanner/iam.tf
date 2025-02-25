resource "random_id" "suffix" {
  byte_length = 4
}

resource "aws_iam_role" "security_scanner" {
  name = "security-scanner-role-${var.environment}-${random_id.suffix.hex}"

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

  tags = merge(
    {
      Name        = "security-scanner-role-${var.environment}"
      Environment = var.environment
    },
    var.tags
  )

  lifecycle {
    create_before_destroy = true
  }
}

resource "aws_iam_instance_profile" "security_scanner" {
  name = "security-scanner-profile-${var.environment}-${random_id.suffix.hex}"
  role = aws_iam_role.security_scanner.name
}

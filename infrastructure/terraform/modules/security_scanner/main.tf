resource "aws_security_group" "security_scanner" {
  name        = "security-scanner-${var.environment}"
  description = "Security group for Security Scanner instance (CodeQL & Dependency Check)"
  vpc_id      = var.vpc_id

  # SSH access
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  # Jenkins port
  ingress {
    from_port   = 8080
    to_port     = 8080
    protocol    = "tcp"
    cidr_blocks = var.allowed_http_cidr_blocks
  }

  # HTTP access
  ingress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = var.allowed_http_cidr_blocks
  }

  # HTTPS access
  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = var.allowed_https_cidr_blocks
  }

  # Flask application port
  ingress {
    from_port   = 5000
    to_port     = 5000
    protocol    = "tcp"
    cidr_blocks = var.allowed_http_cidr_blocks
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = merge(
    {
      Name        = "security-scanner-sg-${var.environment}"
      Environment = var.environment
    },
    var.tags
  )
}

# Move the data source outside of the launch template resource
data "aws_ami" "amazon_linux_2023" {
  most_recent = true
  owners      = ["amazon"]

  filter {
    name   = "name"
    values = ["al2023-ami-*-x86_64"]
  }
}

# Create an Elastic IP for the security scanner instance
resource "aws_eip" "security_scanner" {
  domain = "vpc"
  tags = merge(
    {
      Name        = "security-scanner-eip-${var.environment}"
      Environment = var.environment
      Managed     = "terraform"
    },
    var.tags
  )
}

# Associate the Elastic IP with the EC2 instance
resource "aws_eip_association" "security_scanner" {
  instance_id   = aws_instance.security_scanner.id
  allocation_id = aws_eip.security_scanner.id
}

resource "aws_instance" "security_scanner" {
  ami                         = data.aws_ami.amazon_linux_2023.id
  instance_type               = var.instance_type
  subnet_id                   = var.subnet_id
  vpc_security_group_ids      = [aws_security_group.security_scanner.id]
  associate_public_ip_address = true
  key_name                    = var.key_name
  iam_instance_profile        = aws_iam_instance_profile.security_scanner.name

  root_block_device {
    volume_size = var.volume_size
    volume_type = "gp3"
    encrypted   = true
  }

  user_data = base64encode(<<-EOF
              #!/bin/bash
              
              # Enable logging to both file and console
              exec > >(tee /var/log/user-data.log|logger -t user-data -s 2>/dev/console) 2>&1
              
              echo "Starting setup..."
              
              echo "Installing system packages..."
              dnf update -y
              dnf install -y git wget unzip java-11-amazon-corretto-headless python3 python3-pip nodejs

              echo "Upgrading pip and installing Python dependencies..."
              python3 -m pip install --upgrade pip
              python3 -m pip install flask gitpython --no-cache-dir
              
              echo "Verifying Python packages..."
              python3 -c "import flask; import git; print('Flask and GitPython verified')"

              echo "Creating application directory..."
              mkdir -p /opt/security-scanner
              
              echo "Creating Flask application..."
              cat > /opt/security-scanner/app.py << 'FLASK_APP'
              ${file("${path.module}/files/app.py")}
              FLASK_APP
              
              echo "Creating systemd service file..."
              cat > /etc/systemd/system/security-scanner.service << 'SERVICEEOF'
              [Unit]
              Description=Security Scanner Flask Application
              After=network.target
              
              [Service]
              Type=simple
              User=root
              WorkingDirectory=/opt/security-scanner
              Environment=PATH=/usr/local/bin:/usr/bin:/bin
              ExecStart=/usr/bin/python3 /opt/security-scanner/app.py
              Restart=always
              RestartSec=3
              StandardOutput=append:/var/log/security-scanner.log
              StandardError=append:/var/log/security-scanner.log
              
              [Install]
              WantedBy=multi-user.target
              SERVICEEOF
              
              echo "Setting permissions..."
              chmod 755 /opt/security-scanner/app.py
              chmod 644 /etc/systemd/system/security-scanner.service
              touch /var/log/security-scanner.log
              chmod 644 /var/log/security-scanner.log
              
              echo "Installing CodeQL..."
              CODEQL_VERSION="2.20.4"
              
              # Download CodeQL into a temporary directory
              wget --no-verbose -O /tmp/codeql-linux64.zip "https://github.com/github/codeql-cli-binaries/releases/download/v$${CODEQL_VERSION}/codeql-linux64.zip"
              if [ $? -ne 0 ]; then
                echo "Failed to download CodeQL zip file." && exit 1
              fi

              echo "Extracting CodeQL..."
              unzip -q /tmp/codeql-linux64.zip -d /tmp
              if [ ! -d "/tmp/codeql" ]; then
                echo "CodeQL extraction failed." && exit 1
              fi
              
              echo "Moving CodeQL to /usr/local/ and creating symlink..."
              mv /tmp/codeql /usr/local/
              ln -sf /usr/local/codeql/codeql /usr/local/bin/codeql
              if [ ! -x "/usr/local/bin/codeql" ]; then
                echo "CodeQL installation failed: /usr/local/bin/codeql not found or not executable." && exit 1
              fi

              echo "Verifying CodeQL installation..."
              /usr/local/bin/codeql --version || exit 1

              # Source the CodeQL environment if the file exists (optional)
              [ -f /etc/profile.d/codeql-env.sh ] && source /etc/profile.d/codeql-env.sh

              echo "Downloading CodeQL query suites..."
              cd /opt/security-scanner
              git clone https://github.com/github/codeql.git codeql-queries

              echo "Starting service..."
              systemctl daemon-reload
              systemctl enable security-scanner
              systemctl start security-scanner
              
              echo "Setup complete. Checking service status..."
              systemctl status security-scanner
              EOF
  )

  metadata_options {
    http_tokens = "required"
  }

  tags = merge(
    {
      Name        = "security-scanner-${var.environment}"
      Environment = var.environment
      Managed     = "terraform"
    },
    var.tags
  )
}

data "aws_caller_identity" "current" {}
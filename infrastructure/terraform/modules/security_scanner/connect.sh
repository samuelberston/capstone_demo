# Get the secret name from terraform output
SECRET_NAME=$(terraform output -raw ssh_key_secret_name)

# Get the instance IP
INSTANCE_IP=$(terraform output -raw instance_public_ip)

# Retrieve and save the private key
aws secretsmanager get-secret-value --secret-id $SECRET_NAME \
  --query 'SecretString' --output text | \
  jq -r '.private_key' > security_scanner.pem

# Set correct permissions on the key file
chmod 600 security_scanner.pem

# Now you can SSH to the instance
ssh -i security_scanner.pem ec2-user@$INSTANCE_IP

# Scanner application logs
tail -f /var/log/security-scanner.log
# Start scan
curl -X POST \
  http://localhost:5000/analyze \
  -H 'Content-Type: application/json' \
  -d '{"github_url": "https://github.com/OWASP/juice-shop"}'


# View logs
tail -f /var/log/security-scanner.log
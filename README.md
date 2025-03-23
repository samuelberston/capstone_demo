# Security Scanner

## Usage

### Scan a Repository

```bash
Replace with your actual EC2 endpoint
python scan_cli.py scan --url https://github.com/your-org/your-repo --api-url http://your-ec2-instance:5000
```

### Retrieve Scan Results

```bash
python scan_cli.py results --scan-id 1 --output results.json
results
```

### Options

- `--url`: GitHub repository URL
- `--branch`: Branch to scan (default: main)
- `--api-url`: Security scanner API URL
- `--db-url`: Database URL (default: sqlite:///security_scans.db)
- `--scan-id`: ID of the scan to retrieve
- `--output`: Output file for results (JSON format)

## Features

- CodeQL static analysis scanning
- OWASP Dependency-Check for vulnerable dependencies
- Local database storage of scan results

## Table of Contents

1. [Architecture Overview](./architecture/README.md)
2. [Development Guide](./development/README.md)
3. [API Documentation](./api/README.md)
4. [Setup Guide](./setup/README.md)
5. [Contributing Guide](./CONTRIBUTING.md)
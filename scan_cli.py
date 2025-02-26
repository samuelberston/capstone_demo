#!/usr/bin/env python3
import argparse
import json
import os
from api.client import SecurityScannerClient

def main():
    parser = argparse.ArgumentParser(description='Security Scanner Client')
    subparsers = parser.add_subparsers(dest='command', help='Command to run')
    
    # Scan command
    scan_parser = subparsers.add_parser('scan', help='Scan a repository')
    scan_parser.add_argument('--url', required=True, help='GitHub repository URL')
    scan_parser.add_argument('--branch', default='main', help='Branch to scan (default: main)')
    scan_parser.add_argument('--api-url', required=True, help='Security scanner API URL')
    scan_parser.add_argument('--db-url', default='sqlite:///security_scans.db', 
                            help='Database URL (default: sqlite:///security_scans.db)')
    
    # Results command
    results_parser = subparsers.add_parser('results', help='Get scan results')
    results_parser.add_argument('--scan-id', type=int, required=True, help='Scan ID')
    results_parser.add_argument('--db-url', default='sqlite:///security_scans.db', 
                               help='Database URL (default: sqlite:///security_scans.db)')
    results_parser.add_argument('--output', help='Output file for results (JSON format)')
    
    args = parser.parse_args()
    
    if args.command == 'scan':
        client = SecurityScannerClient(args.api_url, args.db_url)
        scan_id = client.scan_repository(args.url, args.branch)
        print(f"Scan initiated with ID: {scan_id}")
        
    elif args.command == 'results':
        client = SecurityScannerClient("", args.db_url)  # API URL not needed for results
        results = client.get_scan_results(args.scan_id)
        
        if args.output:
            with open(args.output, 'w') as f:
                json.dump(results, f, indent=2)
            print(f"Results saved to {args.output}")
        else:
            print(json.dumps(results, indent=2))
    
    else:
        parser.print_help()

if __name__ == "__main__":
    main() 
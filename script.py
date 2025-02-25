#!/usr/bin/env python3
import json
import sys

def count_findings(sarif_file, include_rules=None):
    if include_rules is None:
        # Only include critical security findings
        include_rules = {
            # Critical injection vulnerabilities
            'js/sql-injection',
            'js/code-injection',
            'js/command-line-injection',
            'js/xss',
            
            # Critical authentication & secrets
            'js/hardcoded-credentials',
            'js/jwt-missing-verification',
            
            # Critical security misconfigurations
            'js/prototype-pollution',
            'js/unsafe-deserialization',
            
            # Critical data exposure
            'js/sensitive-data-exposure',
            
            # Critical infrastructure vulnerabilities
            'js/server-side-request-forgery',
            'js/open-redirect'
        }
    
    try:
        with open(sarif_file, 'r') as f:
            data = json.load(f)
        
        total_findings = 0
        findings_by_rule = {}
        
        # Count results from each run
        for run in data.get('runs', []):
            for result in run.get('results', []):
                rule_id = result.get('ruleId', 'unknown')
                
                # Only include whitelisted rules
                if rule_id not in include_rules:
                    continue
                
                findings_by_rule[rule_id] = findings_by_rule.get(rule_id, 0) + 1
                total_findings += 1
        
        print(f"\nTotal number of critical security findings: {total_findings}")
        if total_findings > 0:
            print("\nBreakdown by rule:")
            for rule, count in findings_by_rule.items():
                print(f"{rule}: {count}")
        else:
            print("No critical security findings detected.")
        
    except FileNotFoundError:
        print(f"Error: File '{sarif_file}' not found")
    except json.JSONDecodeError:
        print("Error: Invalid JSON format")
    except Exception as e:
        print(f"Error: {str(e)}")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python script.py <sarif_file>")
        sys.exit(1)
    
    sarif_file = sys.argv[1]
    count_findings(sarif_file)
import json
from typing import Dict, List
from pathlib import Path

def extract_vulnerabilities(report_path: str) -> List[Dict]:
    """
    Extract detailed vulnerability findings from an OWASP Dependency Check JSON report.
    
    Args:
        report_path: Path to the JSON report file
    
    Returns:
        List of dictionaries containing vulnerability information
    """
    try:
        with open(report_path, 'r') as f:
            report = json.load(f)
        
        # Initialize list to store findings
        findings = []
        
        # Check if dependencies exist in the report
        if 'dependencies' in report:
            for dependency in report['dependencies']:
                # Only process dependencies with vulnerabilities
                if 'vulnerabilities' in dependency:
                    for vuln in dependency['vulnerabilities']:
                        # Extract CVSS v2 details if available
                        cvssv2 = vuln.get('cvssv2', {})
                        cvssv3 = vuln.get('cvssv3', {})
                        
                        finding = {
                            # Dependency details
                            'dependency': dependency.get('fileName', ''),
                            'description': dependency.get('description', ''),
                            'filePath': dependency.get('filePath', ''),
                            'isVirtual': dependency.get('isVirtual', False),
                            'projectReferences': dependency.get('projectReferences', []),
                            
                            # Package information
                            'packages': dependency.get('packages', []),
                            
                            # Vulnerability details
                            'source': vuln.get('source', ''),
                            'name': vuln.get('name', ''),
                            'severity': vuln.get('severity', ''),
                            'cwes': vuln.get('cwes', []),
                            'description': vuln.get('description', ''),
                            
                            # CVSS v3 details
                            'cvssv3': {
                                'baseScore': cvssv3.get('baseScore', ''),
                                'attackVector': cvssv3.get('attackVector', ''),
                                'attackComplexity': cvssv3.get('attackComplexity', ''),
                                'privilegesRequired': cvssv3.get('privilegesRequired', ''),
                                'userInteraction': cvssv3.get('userInteraction', ''),
                                'scope': cvssv3.get('scope', ''),
                                'confidentialityImpact': cvssv3.get('confidentialityImpact', ''),
                                'integrityImpact': cvssv3.get('integrityImpact', ''),
                                'availabilityImpact': cvssv3.get('availabilityImpact', ''),
                                'baseSeverity': cvssv3.get('baseSeverity', ''),
                            },
                            
                            # CVSS v2 details
                            'cvssv2': {
                                'score': cvssv2.get('score', ''),
                                'accessVector': cvssv2.get('accessVector', ''),
                                'accessComplexity': cvssv2.get('accessComplexity', ''),
                                'authenticationr': cvssv2.get('authenticationr', ''),
                                'confidentialityImpact': cvssv2.get('confidentialityImpact', ''),
                                'integrityImpact': cvssv2.get('integrityImpact', ''),
                                'availabilityImpact': cvssv2.get('availabilityImpact', ''),
                                'severity': cvssv2.get('severity', ''),
                            },
                            
                            # References and related info
                            'references': vuln.get('references', []),
                            'vulnerableSoftware': vuln.get('vulnerableSoftware', []),
                        }
                        findings.append(finding)
        
        return findings
    
    except json.JSONDecodeError as e:
        print(f"Error parsing JSON file: {e}")
        return []
    except Exception as e:
        print(f"Error processing file: {e}")
        return []

def main():
    # Replace with your actual report path
    report_path = '/Users/samuelberston/Desktop/dependency-check-report.json'
    
    vulnerabilities = extract_vulnerabilities(report_path)
    
    # Save findings to JSON file
    output_path = Path(report_path).parent / 'vulnerability_findings.json'
    with open(output_path, 'w') as f:
        json.dump(vulnerabilities, f, indent=2)
    print(f"\nFindings saved to: {output_path}")
    
    # Print basic statistics
    print(f"\nVulnerability Statistics:")
    print(f"Total vulnerabilities found: {len(vulnerabilities)}")
    
    # Print list of affected dependencies
    unique_deps = set(v['dependency'] for v in vulnerabilities)
    print("\nAffected Dependencies:")
    for dep in sorted(unique_deps):
        print(f"- {dep}")
    
    # Count vulnerabilities by severity
    severity_counts = {}
    for vuln in vulnerabilities:
        severity = vuln['severity']
        severity_counts[severity] = severity_counts.get(severity, 0) + 1
    
    print("\nVulnerabilities by severity:")
    for severity, count in severity_counts.items():
        print(f"{severity}: {count}")
    
    # Calculate average CVSS score
    cvss_scores = [float(v['cvssv3']['baseScore']) for v in vulnerabilities if v['cvssv3']['baseScore']]
    if cvss_scores:
        avg_cvss = sum(cvss_scores) / len(cvss_scores)
        print(f"\nAverage CVSS score: {avg_cvss:.2f}")
    
    # Count unique affected dependencies
    print(f"Number of affected dependencies: {len(unique_deps)}")

if __name__ == "__main__":
    main()
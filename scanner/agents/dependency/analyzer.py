import logging
from typing import Dict
from dataclasses import dataclass

logger = logging.getLogger(__name__)

@dataclass
class VulnerabilityInfo:
    vulnerabilities: list
    cves: list
    severities: set
    cwes: list

class DependencyAnalyzer:
    @staticmethod
    def extract_vulnerability_info(context: Dict) -> Dict:
        """Extract vulnerability information from dependency-check findings"""
        vuln_info = {
            'vulnerabilities': context.get('vulnerabilities', []),
            'cves': [],
            'severities': set(),
            'cwes': []
        }
        
        for vuln in vuln_info['vulnerabilities']:
            if vuln.get('name', '').startswith('CVE-'):
                vuln_info['cves'].append(vuln['name'])
            vuln_info['severities'].add(vuln.get('severity', '').upper())
            if vuln.get('cwes'):
                vuln_info['cwes'].extend(vuln.get('cwes', []))
        
        return vuln_info

    @staticmethod
    def format_vulnerability_details(vuln_info: Dict) -> str:
        """Format vulnerability details for analysis prompt"""
        details = []
        for vuln in vuln_info.get('vulnerabilities', []):
            details.append(f"""
- ID: {vuln.get('name')}
- Severity: {vuln.get('severity', 'Unknown')}
- Description: {vuln.get('description', 'No description available')}
- CWEs: {', '.join(vuln.get('cwes', []))}
""")
        return '\n'.join(details)

    @staticmethod
    def format_cvss_scores(vuln_info: Dict) -> str:
        """Format CVSS scores for analysis prompt"""
        scores = []
        for vuln in vuln_info.get('vulnerabilities', []):
            if vuln.get('cvssv3'):
                scores.append(f"""
CVSS v3 Score: {vuln['cvssv3'].get('baseScore')} ({vuln['cvssv3'].get('baseSeverity')})
- Attack Vector: {vuln['cvssv3'].get('attackVector')}
- Attack Complexity: {vuln['cvssv3'].get('attackComplexity')}
- Privileges Required: {vuln['cvssv3'].get('privilegesRequired')}
- User Interaction: {vuln['cvssv3'].get('userInteraction')}
""")
        return '\n'.join(scores) if scores else "No CVSS scores available" 
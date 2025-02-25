import requests
import json
import os
import logging
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from database.models import Base, Scan, CodeQLFinding, DependencyCheckFinding

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class SecurityScannerClient:
    def __init__(self, api_url, db_url="sqlite:///security_scans.db"):
        """
        Initialize the security scanner client.
        
        Args:
            api_url: URL of the security scanner API
            db_url: Database connection URL (defaults to local SQLite)
        """
        self.api_url = api_url
        self.engine = create_engine(db_url)
        self.Session = sessionmaker(bind=self.engine)
        
        # Ensure database tables exist
        Base.metadata.create_all(self.engine)
        
    def scan_repository(self, github_url, branch="main"):
        """
        Scan a GitHub repository and save results to the database.
        
        Args:
            github_url: URL of the GitHub repository to scan
            branch: Branch to scan (default: main)
            
        Returns:
            scan_id: ID of the created scan record
        """
        # Create a new scan record
        session = self.Session()
        scan = Scan(
            repository_url=github_url,
            branch=branch,
            status="running"
        )
        session.add(scan)
        session.commit()
        scan_id = scan.id
        
        try:
            # Call the security scanner API
            logger.info(f"Starting scan for {github_url} (branch: {branch})")
            response = requests.post(
                f"{self.api_url}/analyze",
                json={"github_url": github_url},
                timeout=600  # Long timeout as scans can take time
            )
            
            if response.status_code != 200:
                logger.error(f"Scan failed with status code {response.status_code}: {response.text}")
                self._update_scan_status(scan_id, "failed")
                return scan_id
                
            # Process the results
            results = response.json()
            logger.info(f"Scan completed successfully for {github_url}")
            
            # Save CodeQL findings
            self._save_codeql_findings(scan_id, results.get('analysis_results', {}).get('results', []))
            
            # Save dependency check findings
            self._save_dependency_findings(scan_id, results.get('dependency_check', {}).get('results', {}))
            
            # Update scan status
            self._update_scan_status(scan_id, "completed")
            
            return scan_id
            
        except Exception as e:
            logger.error(f"Error during scan: {str(e)}")
            self._update_scan_status(scan_id, "failed")
            return scan_id
    
    def _update_scan_status(self, scan_id, status):
        """Update the status of a scan."""
        session = self.Session()
        try:
            scan = session.query(Scan).get(scan_id)
            if scan:
                scan.status = status
                session.commit()
        finally:
            session.close()
    
    def _save_codeql_findings(self, scan_id, findings):
        """Save CodeQL findings to the database."""
        if not findings:
            return
            
        session = self.Session()
        try:
            for finding in findings:
                # Extract location information
                locations = finding.get('locations', [])
                file_path = ""
                start_line = 0
                start_column = 0
                end_column = 0
                
                if locations and len(locations) > 0:
                    location = locations[0]
                    physical_location = location.get('physicalLocation', {})
                    artifact_location = physical_location.get('artifactLocation', {})
                    file_path = artifact_location.get('uri', '')
                    
                    region = physical_location.get('region', {})
                    start_line = region.get('startLine', 0)
                    start_column = region.get('startColumn', 0)
                    end_column = region.get('endColumn', 0)
                
                # Extract LLM analysis if available
                llm_analysis = finding.get('llm_analysis', {})
                verification = llm_analysis.get('verification', '')
                exploitability = llm_analysis.get('exploitability', '')
                remediation = llm_analysis.get('remediation', '')
                priority = llm_analysis.get('priority', '')
                
                # Create finding record
                codeql_finding = CodeQLFinding(
                    scan_id=scan_id,
                    rule_id=finding.get('ruleId', ''),
                    rule_index=finding.get('ruleIndex', 0),
                    message=finding.get('message', {}).get('text', ''),
                    file_path=file_path,
                    start_line=start_line,
                    start_column=start_column,
                    end_column=end_column,
                    fingerprint=finding.get('partialFingerprints', {}).get('primaryLocationLineHash', ''),
                    llm_verification=verification,
                    llm_exploitability=exploitability,
                    llm_remediation=remediation,
                    llm_priority=priority,
                    raw_data=finding
                )
                session.add(codeql_finding)
            session.commit()
            logger.info(f"Saved {len(findings)} CodeQL findings for scan {scan_id}")
        finally:
            session.close()
    
    def _save_dependency_findings(self, scan_id, results):
        """Save dependency check findings to the database."""
        if not results:
            return
            
        dependencies = results.get('dependencies', [])
        if not dependencies:
            return
            
        session = self.Session()
        try:
            finding_count = 0
            for dependency in dependencies:
                # Skip dependencies with no vulnerabilities
                if not dependency.get('vulnerabilities'):
                    continue
                    
                dependency_name = dependency.get('fileName', '')
                dependency_version = dependency.get('version', '')
                
                # Process each vulnerability
                for vuln in dependency.get('vulnerabilities', []):
                    # Extract LLM analysis if available
                    llm_analysis = vuln.get('llm_analysis', {})
                    exploitability = llm_analysis.get('exploitability', '')
                    remediation = llm_analysis.get('remediation', '')
                    priority = llm_analysis.get('priority', '')
                    
                    finding = DependencyCheckFinding(
                        scan_id=scan_id,
                        dependency_name=dependency_name,
                        dependency_version=dependency_version,
                        vulnerability_id=vuln.get('name', ''),
                        vulnerability_name=vuln.get('name', ''),
                        severity=vuln.get('severity', ''),
                        cvss_score=vuln.get('cvssv3', {}).get('baseScore', 0.0),
                        description=vuln.get('description', ''),
                        llm_exploitability=exploitability,
                        llm_remediation=remediation,
                        llm_priority=priority,
                        raw_data=vuln
                    )
                    session.add(finding)
                    finding_count += 1
                    
            session.commit()
            logger.info(f"Saved {finding_count} dependency findings for scan {scan_id}")
        finally:
            session.close()
    
    def get_scan_results(self, scan_id):
        """
        Get the results of a scan.
        
        Args:
            scan_id: ID of the scan
            
        Returns:
            dict: Scan results including CodeQL and dependency findings
        """
        session = self.Session()
        try:
            scan = session.query(Scan).get(scan_id)
            if not scan:
                return {"error": f"Scan with ID {scan_id} not found"}
                
            codeql_findings = session.query(CodeQLFinding).filter(CodeQLFinding.scan_id == scan_id).all()
            dependency_findings = session.query(DependencyCheckFinding).filter(DependencyCheckFinding.scan_id == scan_id).all()
            
            return {
                "scan": {
                    "id": scan.id,
                    "repository_url": scan.repository_url,
                    "branch": scan.branch,
                    "commit_hash": scan.commit_hash,
                    "scan_date": scan.scan_date.isoformat() if scan.scan_date else None,
                    "status": scan.status
                },
                "codeql_findings": [
                    {
                        "id": finding.id,
                        "rule_id": finding.rule_id,
                        "message": finding.message,
                        "file_path": finding.file_path,
                        "start_line": finding.start_line
                    } for finding in codeql_findings
                ],
                "dependency_findings": [
                    {
                        "id": finding.id,
                        "dependency_name": finding.dependency_name,
                        "dependency_version": finding.dependency_version,
                        "vulnerability_id": finding.vulnerability_id,
                        "severity": finding.severity,
                        "cvss_score": finding.cvss_score
                    } for finding in dependency_findings
                ]
            }
        finally:
            session.close() 
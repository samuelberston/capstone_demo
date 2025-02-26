# api/main.py
from fastapi import FastAPI, HTTPException
from sqlalchemy.orm import sessionmaker
from database.models import Scan, CodeQLFinding, DependencyCheckFinding
from client import SecurityScannerClient

app = FastAPI()

# Initialize the database session
scanner_client = SecurityScannerClient(api_url="http://your-api-url", db_url="postgresql://samuelberston@localhost/security_scan_db")
Session = scanner_client.Session

@app.get("/scans")
def get_all_scan_results():
    session = Session()
    try:
        scans = session.query(Scan).all()
        all_results = []
        
        for scan in scans:
            codeql_findings = session.query(CodeQLFinding).filter(CodeQLFinding.scan_id == scan.id).all()
            dependency_findings = session.query(DependencyCheckFinding).filter(DependencyCheckFinding.scan_id == scan.id).all()
            
            scan_result = {
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
            all_results.append(scan_result)
        
        return all_results
    finally:
        session.close()
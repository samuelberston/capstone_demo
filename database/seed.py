from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from models import Base, Scan, CodeQLFinding, DependencyCheckFinding
import datetime
import os

# Get database URL from environment variable or use default
DATABASE_URL = os.getenv('DATABASE_URL', 'sqlite:///security_scanner.db')

# Create engine and session
engine = create_engine(DATABASE_URL)
Base.metadata.create_all(engine)  # Ensure tables are created

Session = sessionmaker(bind=engine)
session = Session()

def seed_database():
    # Create sample scan entries
    scans = [
        Scan(
            repository_url="https://github.com/example/vulnerable-app",
            branch="main",
            commit_hash="a1b2c3d4e5f6g7h8i9j0",
            scan_date=datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=1),
            status="completed"
        ),
        Scan(
            repository_url="https://github.com/example/secure-app",
            branch="master",
            commit_hash="1a2b3c4d5e6f7g8h9i0j",
            scan_date=datetime.datetime.now(datetime.timezone.utc),
            status="completed"
        )
    ]
    
    session.add_all(scans)
    session.flush()

    # Create sample CodeQL findings
    codeql_findings = [
        CodeQLFinding(
            scan_id=scans[0].id,
            rule_id="js/sql-injection",
            rule_index=1,
            message="Possible SQL injection vulnerability in query construction",
            file_path="src/controllers/user.js",
            start_line=45,
            start_column=10,
            end_column=50,
            fingerprint="abc123def456",
            llm_verification="The finding appears to be a true positive. The code directly concatenates user input into SQL queries.",
            llm_exploitability="High - The vulnerability is easily exploitable using simple SQL injection payloads.",
            llm_remediation="Use parameterized queries or an ORM to safely handle user input in database queries.",
            llm_priority="High priority - Should be fixed immediately due to high exploitability and potential impact.",
            raw_data={"severity": "critical", "confidence": "high"}
        ),
        CodeQLFinding(
            scan_id=scans[0].id,
            rule_id="js/xss",
            rule_index=2,
            message="Cross-site scripting vulnerability due to unescaped output",
            file_path="src/views/profile.js",
            start_line=23,
            start_column=5,
            end_column=35,
            fingerprint="xyz789abc012",
            llm_verification="Confirmed true positive. User input is rendered directly to HTML without sanitization.",
            llm_exploitability="Medium - Requires user interaction but could lead to session hijacking.",
            llm_remediation="Use appropriate HTML escaping functions or React's built-in XSS protection.",
            llm_priority="Medium priority - Should be addressed in the next sprint.",
            raw_data={"severity": "high", "confidence": "high"}
        )
    ]
    
    session.add_all(codeql_findings)

    # Create sample dependency check findings
    dependency_findings = [
        DependencyCheckFinding(
            scan_id=scans[0].id,
            dependency_name="log4j-core",
            dependency_version="2.14.1",
            vulnerability_id="CVE-2021-44228",
            vulnerability_name="Log4Shell",
            severity="CRITICAL",
            cvss_score=10.0,
            description="Remote code execution vulnerability in Apache Log4j",
            llm_exploitability="Critical - Widely exploited in the wild with publicly available proof of concept.",
            llm_remediation="Upgrade to Log4j 2.15.0 or later immediately.",
            llm_priority="Critical priority - Requires immediate patching due to active exploitation.",
            raw_data={"cwe": "CWE-502", "references": ["https://nvd.nist.gov/vuln/detail/CVE-2021-44228"]}
        ),
        DependencyCheckFinding(
            scan_id=scans[1].id,
            dependency_name="jquery",
            dependency_version="3.3.1",
            vulnerability_id="CVE-2019-11358",
            vulnerability_name="Prototype Pollution",
            severity="MEDIUM",
            cvss_score=6.1,
            description="jQuery before 3.4.0 is vulnerable to prototype pollution",
            llm_exploitability="Low - Requires specific conditions and complex exploitation chain.",
            llm_remediation="Update jQuery to version 3.4.0 or later.",
            llm_priority="Low priority - Can be addressed in regular maintenance cycle.",
            raw_data={"cwe": "CWE-915", "references": ["https://nvd.nist.gov/vuln/detail/CVE-2019-11358"]}
        )
    ]
    
    session.add_all(dependency_findings)
    session.commit()

if __name__ == "__main__":
    print("Seeding database...")
    seed_database()
    print("Database seeded successfully!") 
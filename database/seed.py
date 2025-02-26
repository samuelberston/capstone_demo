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
            repository_url="https://github.com/juice-shop/juice-shop",
            branch="main",
            commit_hash="",
            scan_date=datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=1),
            status="completed"
        )
    ]
    
    session.add_all(scans)
    session.flush()

    # Create sample CodeQL findings
    codeql_findings = [
        CodeQLFinding(
            scan_id=scans[0].id,
            rule_id="js/sensitive-get-query",
            rule_index=75,
            message="Route handler for GET requests uses query parameter as sensitive data",
            file_path="routes/changePassword.ts",
            start_line=17,
            start_column=25,
            end_column=34,
            fingerprint="6fbcb4891477c828:1",
            llm_verification="This is a true positive. The code uses GET query parameters to transmit sensitive password data, which is a security risk as these parameters can be logged and appear in browser history.",
            llm_exploitability="High - Password data in GET parameters can be exposed through browser history, server logs, and referrer headers.",
            llm_remediation="Use POST method instead of GET for password changes. Sensitive data should be sent in the request body, not as query parameters.",
            llm_priority="High priority - This violates security best practices for handling sensitive data and should be fixed immediately.",
            raw_data={
                "relatedLocations": [{
                    "message": "Route handler",
                    "line": 15,
                    "startColumn": 10,
                    "endLine": 48,
                    "endColumn": 4
                }]
            }
        ),
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
            dependency_name="express-jwt",
            dependency_version="0.1.3",
            vulnerability_id="CVE-2020-15084",
            vulnerability_name="Authorization Bypass",
            severity="CRITICAL",
            cvss_score=9.1,
            description="In express-jwt (NPM package) up and including version 5.3.3, the algorithms entry to be specified in the configuration is not being enforced. When algorithms is not specified in the configuration, with the combination of jwks-rsa, it may lead to authorization bypass.",
            llm_exploitability="High - The vulnerability allows bypassing authentication when specific conditions are met.",
            llm_remediation="Update express-jwt to version 6.0.0 or later and ensure 'algorithms' is specified in the express-jwt configuration.",
            llm_priority="Critical priority - This vulnerability could lead to unauthorized access and should be patched immediately.",
            raw_data={"cwe": "CWE-287", "references": ["https://nvd.nist.gov/vuln/detail/CVE-2020-15084"]}
        ),
        DependencyCheckFinding(
            scan_id=scans[0].id,
            dependency_name="nanoid",
            dependency_version="3.1.20",
            vulnerability_id="CVE-2021-23566",
            vulnerability_name="Information Exposure",
            severity="MEDIUM",
            cvss_score=5.5,
            description="The package nanoid from 3.0.0 and before 3.1.31 are vulnerable to Information Exposure via the valueOf() function which allows to reproduce the last id generated.",
            llm_exploitability="Medium - An attacker could potentially predict or reproduce generated IDs, leading to information disclosure.",
            llm_remediation="Update nanoid to version 3.1.31 or later to prevent exposure of generated IDs through valueOf() function.",
            llm_priority="Medium priority - While not critical, this should be addressed to prevent potential ID prediction attacks.",
            raw_data={"cwe": "CWE-200", "references": ["https://nvd.nist.gov/vuln/detail/CVE-2021-23566"]}
        )
    ]
    
    session.add_all(dependency_findings)
    session.commit()

if __name__ == "__main__":
    print("Seeding database...")
    seed_database()
    print("Database seeded successfully!") 
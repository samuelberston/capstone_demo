from flask import Flask, request, jsonify
from flask_cors import CORS
import git
import tempfile
import logging
import os
import threading
from datetime import datetime
# Fix the import to be relative since we're in the scanner package
from .scan import detect_all_languages, run_codeql_analysis, run_dependency_check
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from database.models import Base, Scan, CodeQLFinding, DependencyCheckFinding

# Create the Flask application
def create_app():
    app = Flask(__name__)
    CORS(app)
    
    # Configure logging
    logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    logger = logging.getLogger(__name__)
    
    # Database setup
    DATABASE_URL = "postgresql://samuelberston@localhost/security_scan_db"
    engine = create_engine(DATABASE_URL)
    Session = sessionmaker(bind=engine)
    
    def run_scan(scan_id, github_url, session):
        try:
            with tempfile.TemporaryDirectory() as temp_dir:
                try:
                    logger.info("Cloning repository...")
                    repo = git.Repo.clone_from(
                        github_url,
                        temp_dir,
                        env={'GIT_TERMINAL_PROMPT': '0'},
                        config='http.sslVerify=true',
                        allow_unsafe_options=True
                    )
                    
                    # Get the commit hash
                    commit_hash = repo.head.object.hexsha[:7]
                    logger.info(f"Got commit hash: {commit_hash}")
                    
                    # Update scan record with commit hash
                    scan = session.query(Scan).filter_by(id=scan_id).first()
                    if scan:
                        scan.commit_hash = commit_hash
                        scan.status_message = f'Repository cloned successfully at commit {commit_hash}'
                        session.commit()
                        logger.info(f"Updated scan {scan_id} with commit hash {commit_hash}")
                    else:
                        logger.error(f"Could not find scan record with ID {scan_id}")
                        return
                    
                    # Refresh the session to ensure we have the latest data
                    session.refresh(scan)
                    
                    logger.info("Detecting languages...")
                    detected_languages = detect_all_languages(temp_dir)
                    logger.debug(f"Detected languages: {detected_languages}")
                    
                    if not detected_languages:
                        detected_languages = ['python']

                    combined_results = []
                    saved_files = []

                    # Run CodeQL analysis for each detected language
                    for lang in detected_languages:
                        # Update scan status
                        scan = session.query(Scan).filter_by(id=scan_id).first()
                        if scan:
                            scan.status_message = f'Running CodeQL analysis for {lang}'
                            scan.progress_percentage = 20
                            session.commit()

                        analysis = run_codeql_analysis(temp_dir, lang)
                        
                        if not analysis.get("success"):
                            scan = session.query(Scan).filter_by(id=scan_id).first()
                            if scan:
                                scan.status = 'failed'
                                scan.error_message = analysis.get("error", "Unknown error during CodeQL analysis")
                                session.commit()
                            return

                        # Extract results from the analysis
                        results = analysis.get("results", {}).get("runs", [{}])[0].get("results", [])
                        combined_results.extend(results)

                    # Run OWASP Dependency-Check
                    if session and scan_id:
                        scan = session.query(Scan).filter_by(id=scan_id).first()
                        if scan:
                            scan.status_message = 'Installing project dependencies'
                            scan.progress_percentage = 65
                            session.commit()

                    dependency_check_results = run_dependency_check(temp_dir, session, scan_id)
                    
                    if 'error' in dependency_check_results:
                        scan = session.query(Scan).filter_by(id=scan_id).first()
                        if scan:
                            scan.status = 'failed'
                            scan.error_message = dependency_check_results['error']
                            session.commit()
                        return

                    # Store results in database
                    for finding in combined_results:
                        codeql_finding = CodeQLFinding(
                            scan_id=scan_id,
                            rule_id=finding.get('ruleId'),
                            message=finding.get('message', {}).get('text'),
                            file_path=finding.get('locations', [{}])[0].get('physicalLocation', {}).get('artifactLocation', {}).get('uri'),
                            start_line=finding.get('locations', [{}])[0].get('physicalLocation', {}).get('region', {}).get('startLine'),
                            raw_data=finding
                        )
                        session.add(codeql_finding)
                    
                    scan = session.query(Scan).filter_by(id=scan_id).first()
                    if scan:
                        scan.status = 'completed'
                        scan.progress_percentage = 100
                        scan.status_message = 'Scan completed successfully'
                        session.commit()

                except git.GitCommandError as e:
                    logger.error(f"Git clone error: {str(e)}")
                    scan = session.query(Scan).filter_by(id=scan_id).first()
                    if scan:
                        scan.status = 'failed'
                        scan.error_message = f'Failed to clone repository: {str(e)}'
                        session.commit()
                except Exception as e:
                    logger.error(f"Analysis error: {str(e)}", exc_info=True)
                    scan = session.query(Scan).filter_by(id=scan_id).first()
                    if scan:
                        scan.status = 'failed'
                        scan.error_message = f'Analysis failed: {str(e)}'
                        session.commit()
        finally:
            session.close()
    
    @app.route('/health', methods=['GET'])
    def health_check():
        return jsonify({'status': 'healthy'})
    
    @app.route('/test', methods=['GET'])
    def test():
        return jsonify({'status': 'ok'})
    
    @app.route('/analyze', methods=['POST'])
    def analyze_repo():
        logger.info("Received analyze request")
        session = Session()
        try:
            data = request.get_json()
            logger.debug(f"Received data: {data}")
            
            if not data or 'github_url' not in data:
                logger.error("Missing github_url in request")
                return jsonify({'error': 'GitHub URL is required'}), 400

            github_url = data['github_url']
            logger.info(f"Analyzing repository: {github_url}")
            
            # Create scan record first
            scan = Scan(
                repository_url=github_url,
                branch='main',
                status='running',
                scan_date=datetime.utcnow(),
                progress_percentage=0,
                status_message='Initializing scan'
            )
            session.add(scan)
            session.commit()
            logger.info(f"Created scan record with ID: {scan.id}")
            
            if not github_url.endswith('.git'):
                github_url = f"{github_url}.git"
            
            # Start scan in background thread
            thread = threading.Thread(
                target=run_scan,
                args=(scan.id, github_url, Session())
            )
            thread.daemon = True
            thread.start()
            
            return jsonify({
                'message': 'Scan started successfully',
                'scan_id': scan.id
            })

        except Exception as e:
            logger.error(f"Error starting scan: {str(e)}", exc_info=True)
            return jsonify({'error': f'Failed to start scan: {str(e)}'}), 500
        finally:
            session.close()
    
    @app.route('/scans', methods=['GET'])
    def get_scans():
        session = Session()
        try:
            scans = session.query(Scan).all()
            return jsonify({
                'scans': [{
                    'id': scan.id,
                    'repository_url': scan.repository_url,
                    'branch': scan.branch,
                    'commit_hash': scan.commit_hash,
                    'status': scan.status,
                    'scan_date': scan.scan_date.isoformat() if scan.scan_date else None,
                    'progress_percentage': scan.progress_percentage,
                    'status_message': scan.status_message,
                    'error_message': scan.error_message,
                    'codeql_findings': [{
                        'id': f.id,
                        'scan_id': f.scan_id,
                        'rule_id': f.rule_id,
                        'message': f.message,
                        'file_path': f.file_path,
                        'start_line': f.start_line,
                        'llm_verification': f.llm_verification,
                        'llm_exploitability': f.llm_exploitability,
                        'llm_priority': f.llm_priority,
                        'code_context': f.code_context,
                        'analysis': f.analysis
                    } for f in scan.codeql_findings],
                    'dependency_findings': [{
                        'id': f.id,
                        'scan_id': f.scan_id,
                        'dependency_name': f.dependency_name,
                        'dependency_version': f.dependency_version,
                        'vulnerability_id': f.vulnerability_id,
                        'vulnerability_name': f.vulnerability_name,
                        'severity': f.severity,
                        'cvss_score': f.cvss_score,
                        'description': f.description,
                        'llm_exploitability': f.llm_exploitability,
                        'llm_priority': f.llm_priority,
                        'analysis': f.analysis
                    } for f in scan.dependency_findings]
                } for scan in scans]
            })
        finally:
            session.close()
    
    @app.route('/scans/reset', methods=['POST'])
    def reset_stuck_scans():
        session = Session()
        try:
            stuck_scans = session.query(Scan).filter_by(status='running').all()
            for scan in stuck_scans:
                scan.status = 'failed'
                scan.error_message = 'Scan was reset due to timeout'
            session.commit()
            return jsonify({'message': f'Reset {len(stuck_scans)} stuck scans'})
        finally:
            session.close()
    
    @app.route('/scans/clear-failed', methods=['POST'])
    def clear_failed_scans():
        session = Session()
        try:
            # Delete all scans with 'failed' status
            failed_scans = session.query(Scan).filter_by(status='failed').all()
            for scan in failed_scans:
                session.delete(scan)
            session.commit()
            return jsonify({'message': f'Cleared {len(failed_scans)} failed scans'})
        except Exception as e:
            session.rollback()
            return jsonify({'error': f'Failed to clear scans: {str(e)}'}), 500
        finally:
            session.close()
    
    return app

# Create the app instance
app = create_app()

if __name__ == '__main__':
    app.run(debug=True)
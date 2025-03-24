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
                scan = session.query(Scan).filter_by(id=scan_id).first()
                if scan:
                    # Initialize progress tracking
                    scan.current_step = 'cloning'
                    scan.progress_percentage = 0
                    scan.status_message = 'Starting repository clone'
                    session.commit()

                try:
                    # Cloning (0-20%)
                    logger.info("Cloning repository...")
                    repo = git.Repo.clone_from(
                        github_url,
                        temp_dir,
                        env={'GIT_TERMINAL_PROMPT': '0'},
                        config='http.sslVerify=true',
                        allow_unsafe_options=True
                    )
                    
                    scan.progress_percentage = 20
                    scan.current_step = 'language_detection'
                    scan.status_message = 'Repository cloned, detecting languages'
                    session.commit()

                    # Language detection (20-30%)
                    logger.info("Detecting languages...")
                    detected_languages = detect_all_languages(temp_dir)
                    
                    scan.progress_percentage = 30
                    scan.status_message = f'Detected languages: {", ".join(detected_languages)}'
                    session.commit()

                    # Start parallel scans (30-100%)
                    scan.current_step = 'scanning'
                    scan.status_message = 'Running security scans'
                    session.commit()

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
                    
                    if not detected_languages:
                        detected_languages = ['python']

                    # Create threads for parallel execution
                    codeql_thread = threading.Thread(
                        target=run_codeql_scans,
                        args=(temp_dir, detected_languages, scan_id, Session())
                    )
                    
                    dependency_thread = threading.Thread(
                        target=run_dependency_scan,
                        args=(temp_dir, scan_id, Session())
                    )

                    # Start both scans in parallel
                    codeql_thread.start()
                    dependency_thread.start()

                    # Wait for both scans to complete
                    codeql_thread.join()
                    dependency_thread.join()

                    # Update final scan status
                    scan = session.query(Scan).filter_by(id=scan_id).first()
                    if scan and scan.status != 'failed':
                        scan.status = 'completed'
                        scan.progress_percentage = 100
                        scan.status_message = 'Scan completed successfully'
                        session.commit()

                    # Add parallel task tracking
                    scan.codeql_status = 'completed'
                    scan.dependency_status = 'completed'
                    scan.status_message = 'Running CodeQL and Dependency analyses'
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
    
    def run_codeql_scans(temp_dir, detected_languages, scan_id, session):
        try:
            scan = session.query(Scan).filter_by(id=scan_id).first()
            start_time = datetime.utcnow()

            for idx, lang in enumerate(detected_languages):
                scan.status_message = f'CodeQL: {lang} ({idx + 1}/{len(detected_languages)}) - Est. {(len(detected_languages) - idx) * 2} mins remaining'
                session.commit()

                analysis = run_codeql_analysis(temp_dir, lang)
                
                if not analysis.get("success"):
                    scan.codeql_status = 'failed'  # Update specific status
                    scan.error_message = analysis.get("error")
                    session.commit()
                    return

            scan.codeql_status = 'completed'
            session.commit()

        except Exception as e:
            logger.error(f"CodeQL analysis error: {str(e)}", exc_info=True)
            scan = session.query(Scan).filter_by(id=scan_id).first()
            if scan:
                scan.codeql_status = 'failed'
                scan.error_message = f'CodeQL analysis failed: {str(e)}'
                session.commit()
        finally:
            session.close()

    def run_dependency_scan(temp_dir, scan_id, session):
        try:
            scan = session.query(Scan).filter_by(id=scan_id).first()
            start_time = datetime.utcnow()
            
            scan.status_message = 'Dependency Check: Installing dependencies - Est. 5-10 mins'
            session.commit()
            
            dependency_check_results = run_dependency_check(temp_dir, session, scan_id)
            
            if 'error' in dependency_check_results:
                scan.dependency_status = 'failed'  # Update specific status
                scan.error_message = dependency_check_results['error']
                session.commit()
                return

            scan.dependency_status = 'completed'
            session.commit()

        except Exception as e:
            logger.error(f"Dependency check error: {str(e)}", exc_info=True)
            scan = session.query(Scan).filter_by(id=scan_id).first()
            if scan:
                scan.dependency_status = 'failed'
                scan.error_message = f'Dependency check failed: {str(e)}'
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
                    'current_step': scan.current_step,
                    'codeql_status': scan.codeql_status,
                    'dependency_status': scan.dependency_status,
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
                        'code_context': getattr(f, 'code_context', None),
                        'analysis': f.raw_data.get('analysis', {}) if f.raw_data else {}
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
                        'analysis': f.raw_data.get('analysis', {}) if f.raw_data else {}
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
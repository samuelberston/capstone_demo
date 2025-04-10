import subprocess
import os
import tempfile
import json
import uuid
import logging
from pathlib import Path
import shutil
import time
from datetime import datetime, timedelta
from typing import Dict, Any

# Use relative imports instead of absolute
from .agents.code_agent import CodeAnalysisAgent
from .agents.dependency import DependencyAnalysisAgent
from database.models import Scan, CodeQLFinding, DependencyCheckFinding

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Update paths to work both locally and in /opt
BASE_DIR = os.getenv('SECURITY_SCANNER_DIR', '/opt/security-scanner')
CODEQL_QUERIES_PATH = os.getenv('CODEQL_QUERIES_PATH', os.path.join(BASE_DIR, "codeql-queries"))
DATA_DIR = os.getenv('SECURITY_SCANNER_DATA', os.path.join(BASE_DIR, "data"))
os.makedirs(DATA_DIR, exist_ok=True)

# Add cache directory
CACHE_DIR = os.getenv('SECURITY_SCANNER_DATA', os.path.join(BASE_DIR, "data"))
os.makedirs(CACHE_DIR, exist_ok=True)

def detect_all_languages(repo_path):
    """
    Return a list of all detected languages based on file extensions.
    """
    logger.info(f"Starting language detection in {repo_path}")
    language_stats = {}
    
    extensions = {
        '.py': 'python',
        '.js': 'javascript',
        '.ts': 'javascript',
        '.java': 'java',
        '.cpp': 'cpp',
        '.cc': 'cpp',
        '.c': 'cpp',
        '.cs': 'csharp',
        '.go': 'go',
        '.rb': 'ruby'
    }
    
    file_count = 0
    for root, _, files in os.walk(repo_path):
        if '.git' in root:
            continue
        
        for file in files:
            file_count += 1
            if file_count % 100 == 0:
                logger.info(f"Processed {file_count} files...")
                
            ext = os.path.splitext(file)[1].lower()
            if ext in extensions:
                lang = extensions[ext]
                language_stats[lang] = language_stats.get(lang, 0) + 1
                logger.debug(f"Found {lang} file: {file}")
    
    detected_languages = list(language_stats.keys())
    logger.info(f"Language detection complete. Found {len(detected_languages)} languages: {detected_languages}")
    logger.info(f"Total files processed: {file_count}")
    return detected_languages

def get_query_suite_path(language: str) -> str:
    """Get the path to the CodeQL query suite for the given language."""
    if language == "javascript":
        # Use the standard security and quality suite for JavaScript
        return "javascript-security-and-quality.qls" 
    elif language == "python":
        # Use the standard security and quality suite for Python
        return "python-security-and-quality.qls"
    # Add cases for other languages (java, csharp, etc.)
    # elif language == "java":
    #     return "java-security-extended.qls" 
    else:
        # Maybe default to a basic suite or raise an error
        logger.warning(f"No specific security suite defined for language: {language}. Consider adding one.")
        # Returning a basic query pack path might be a fallback
        # return "codeql/quick-query" # Example, adjust as needed
        raise ValueError(f"Unsupported language or no suite defined: {language}")

def get_cache_key(repo_path, language):
    """Generate a unique cache key based on repo path and language."""
    repo_hash = str(hash(repo_path))
    return f"{repo_hash}_{language}"

def get_cached_results(repo_path, language):
    """Check if there are cached results less than 24 hours old."""
    cache_key = get_cache_key(repo_path, language)
    cache_file = os.path.join(CACHE_DIR, f"{cache_key}.json")
    
    if os.path.exists(cache_file):
        with open(cache_file, 'r') as f:
            cached_data = json.load(f)
            cache_time = datetime.fromtimestamp(cached_data['timestamp'])
            
            if datetime.now() - cache_time < timedelta(hours=24):
                logger.info(f"Using cached CodeQL results for {repo_path} ({language})")
                return cached_data['results']
    return None

def save_to_cache(repo_path, language, results):
    """Save analysis results to cache."""
    cache_key = get_cache_key(repo_path, language)
    cache_file = os.path.join(CACHE_DIR, f"{cache_key}.json")
    
    cache_data = {
        'timestamp': time.time(),
        'results': results
    }
    
    with open(cache_file, 'w') as f:
        json.dump(cache_data, f)

def run_codeql_analysis(repo_path: str, language: str) -> Dict[str, Any]:
    """Run CodeQL analysis on the repository."""
    try:
        logger.info(f"Starting CodeQL analysis for {language} in {repo_path}")
        
        # Create a temporary directory for the CodeQL database
        with tempfile.TemporaryDirectory() as temp_dir:
            db_path = os.path.join(temp_dir, "codeql_db")
            results_path = os.path.join(temp_dir, "results.sarif")
            
            logger.info(f"Creating CodeQL database at {db_path}")
            # Create CodeQL database
            create_db_cmd = [
                "codeql", "database", "create",
                "--language=" + language,
                "--source-root", repo_path,
                "--verbose",
                db_path
            ]
            
            logger.info(f"Running command: {' '.join(create_db_cmd)}")
            result = subprocess.run(
                create_db_cmd,
                capture_output=True,
                text=True,
                check=True
            )
            logger.info("CodeQL database created successfully")
            
            # Determine the query or suite to run
            query_target = ""
            if language == "javascript":
                query_target = "codeql/javascript-queries"
                logger.info(f"Using standard JavaScript query pack: {query_target}")
            else:
                # Fallback to using the suite path for other languages
                query_target = get_query_suite_path(language)
                logger.info(f"Using query suite path: {query_target}")

            # Run CodeQL analysis
            analyze_cmd = [
                "codeql", "database", "analyze",
                db_path,
                query_target,  # Use the determined query target
                "--format=sarif-latest",
                "--output=" + results_path
            ]
            
            logger.info(f"Running command: {' '.join(analyze_cmd)}")
            result = subprocess.run(
                analyze_cmd,
                capture_output=True,
                text=True,
                check=True
            )
            logger.info("CodeQL analysis completed successfully")
            
            # Read and parse results
            logger.info(f"Reading results from {results_path}")
            with open(results_path, 'r') as f:
                results = json.load(f)
                
            logger.info(f"Found {len(results.get('runs', [{}])[0].get('results', []))} results")
            return {
                "success": True,
                "results": results
            }
            
    except subprocess.CalledProcessError as e:
        logger.error(f"CodeQL command failed: {e.stderr}")
        return {
            "success": False,
            "error": f"CodeQL command failed: {e.stderr}"
        }
    except Exception as e:
        logger.error(f"Error running CodeQL analysis: {str(e)}", exc_info=True)
        return {
            "success": False,
            "error": f"Error running CodeQL analysis: {str(e)}"
        }

def get_dependency_cache_key(repo_path: str) -> str:
    """Generate a unique cache key for dependency check results."""
    repo_hash = str(hash(repo_path))
    return f"depcheck_{repo_hash}"

def get_cached_dependency_results(repo_path: str) -> dict:
    """Check if there are cached dependency check results less than 24 hours old."""
    cache_key = get_dependency_cache_key(repo_path)
    cache_file = os.path.join(CACHE_DIR, f"{cache_key}.json")
    
    if os.path.exists(cache_file):
        with open(cache_file, 'r') as f:
            cached_data = json.load(f)
            cache_time = datetime.fromtimestamp(cached_data['timestamp'])
            
            if datetime.now() - cache_time < timedelta(hours=24):
                logger.info(f"Using cached dependency check results for {repo_path}")
                return cached_data['results']
    return None

def save_dependency_results_to_cache(repo_path: str, results: dict) -> None:
    """Save dependency check results to cache."""
    cache_key = get_dependency_cache_key(repo_path)
    cache_file = os.path.join(CACHE_DIR, f"{cache_key}.json")
    
    cache_data = {
        'timestamp': time.time(),
        'results': results
    }
    
    with open(cache_file, 'w') as f:
        json.dump(cache_data, f)
        logger.info(f"Saved dependency check results to cache: {cache_file}")

def run_dependency_check(repo_path, session=None, scan_id=None):
    """
    Run OWASP Dependency-Check on the repository and return results.
    """
    try:
        if session and scan_id:
            scan = session.query(Scan).filter_by(id=scan_id).first()
            if scan:
                scan.status_message = 'Dependency Check: Installing npm packages - Est. 3-5 mins'
                session.commit()

        # Initialize the dependency analysis agent
        dep_agent = DependencyAnalysisAgent(repo_path=repo_path)
        
        logger.info(f"Starting dependency check analysis for repo: {repo_path}")
        
        if session and scan_id:
            scan = session.query(Scan).filter_by(id=scan_id).first()
            if scan:
                scan.status_message = 'Installing project dependencies'
                scan.progress_percentage = 65
                session.commit()

        # Install dependencies based on project type
        if os.path.exists(os.path.join(repo_path, 'package.json')):
            logger.info("Detected Node.js project, checking npm availability...")
            
            # Try to find npm in common locations
            npm_paths = [
                '/usr/local/bin/npm',
                '/usr/bin/npm',
                '/opt/homebrew/bin/npm',  # macOS Homebrew
                os.path.expanduser('~/.nvm/versions/node/*/bin/npm')  # NVM installations
            ]
            
            npm_path = None
            for path in npm_paths:
                if '*' in path:
                    import glob
                    matches = glob.glob(path)
                    if matches:
                        npm_path = matches[0]
                        break
                elif os.path.exists(path):
                    npm_path = path
                    break
            
            if not npm_path:
                logger.error("npm not found in any common locations")
                raise RuntimeError("npm is not installed or not found in PATH")
            
            logger.info(f"Using npm at: {npm_path}")
            
            # First check if package-lock.json exists
            if os.path.exists(os.path.join(repo_path, 'package-lock.json')):
                logger.info("Found package-lock.json, using npm ci for clean install")
                result = subprocess.run([npm_path, 'ci'], 
                                     cwd=repo_path, 
                                     capture_output=True, 
                                     text=True)
                if result.returncode != 0:
                    logger.error(f"npm ci failed: {result.stderr}")
                    raise subprocess.CalledProcessError(result.returncode, [npm_path, 'ci'], result.stdout, result.stderr)
            else:
                logger.info("No package-lock.json found, running npm install")
                # Use --no-audit to speed up installation
                result = subprocess.run([npm_path, 'install', '--no-audit'], 
                                     cwd=repo_path, 
                                     capture_output=True, 
                                     text=True)
                if result.returncode != 0:
                    logger.error(f"npm install failed: {result.stderr}")
                    raise subprocess.CalledProcessError(result.returncode, [npm_path, 'install'], result.stdout, result.stderr)
            
            logger.info("Node.js dependencies installed successfully")
        
        if os.path.exists(os.path.join(repo_path, 'requirements.txt')):
            logger.info("Detected Python project, installing dependencies...")
            subprocess.run(['pip', 'install', '-r', 'requirements.txt'],
                         cwd=repo_path, check=True)
        
        if os.path.exists(os.path.join(repo_path, 'pom.xml')):
            logger.info("Detected Maven project, installing dependencies...")
            subprocess.run(['mvn', 'dependency:resolve'],
                         cwd=repo_path, check=True)
        
        if os.path.exists(os.path.join(repo_path, 'build.gradle')):
            logger.info("Detected Gradle project, installing dependencies...")
            subprocess.run(['gradle', 'dependencies'],
                         cwd=repo_path, check=True)

        if session and scan_id:
            scan = session.query(Scan).filter_by(id=scan_id).first()
            if scan:
                scan.status_message = 'Dependency Check: Analyzing vulnerabilities - Est. 5-7 mins'
                session.commit()

        # Get NVD API key from environment
        nvd_api_key = os.getenv('NVD_API_KEY')
        if not nvd_api_key:
            logger.warning("NVD API key not found in environment variables")

        # Create a unique output directory for this scan
        output_dir = os.path.join(DATA_DIR, f"depcheck_{uuid.uuid4().hex}")
        logger.info(f"Created output directory: {output_dir}")
        
        # Run dependency-check with NVD API key
        cmd = [
            'dependency-check',
            '--scan', repo_path,
            '--format', 'JSON',
            '--format', 'HTML',
            '--out', output_dir,
            '--enableExperimental',
            '--failOnCVSS', '7'
        ]

        # Add NVD API key if available
        if nvd_api_key:
            cmd.extend(['--nvdApiKey', nvd_api_key])
            logger.info("Using NVD API key for faster updates")

        # Add error handling for the subprocess
        try:
            result = subprocess.run(cmd, 
                                  check=True, 
                                  capture_output=True,
                                  text=True)
        except subprocess.CalledProcessError as e:
            logger.error(f"Dependency check process failed: {e.stderr}")
            # Check if we got partial results despite errors
            if os.path.exists(os.path.join(output_dir, "dependency-check-report.json")):
                logger.info("Partial results found, continuing with analysis")
            else:
                raise

        if session and scan_id:
            scan = session.query(Scan).filter_by(id=scan_id).first()
            if scan:
                scan.status_message = 'Dependency Check: Processing results - Est. 1-2 mins'
                session.commit()

        # Read and parse the JSON results
        with open(os.path.join(output_dir, "dependency-check-report.json"), 'r') as f:
            results = json.load(f)
              
        # Log summary of dependencies found
        if 'results' in results:
            dependencies = results.get('results', {}).get('dependencies', [])
            logger.info(f"Found {len(dependencies)} total dependencies")
            
            # Count vulnerabilities by severity
            vuln_counts = {'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}
            for dep in dependencies:
                for vuln in dep.get('vulnerabilities', []):
                    severity = vuln.get('severity', 'UNKNOWN')
                    vuln_counts[severity] = vuln_counts.get(severity, 0) + 1
            
            logger.info(f"Vulnerability summary: {vuln_counts['HIGH']} High, {vuln_counts['MEDIUM']} Medium, {vuln_counts['LOW']} Low")
              
        # Add LLM reasoning to dependency findings and save to database
        if 'results' in results and session and scan_id:
            dependencies = results.get('results', {}).get('dependencies', [])
            if dependencies:
                logger.info(f"Enhancing dependency findings with LLM reasoning")
                enhanced_dependencies = []
                for i, dependency in enumerate(dependencies, 1):
                    if dependency.get('vulnerabilities'):
                        logger.info(f"Analyzing dependency {i}/{len(dependencies)}: {dependency.get('fileName', 'Unknown')}")
                        try:
                            # Use the dependency analysis agent to analyze each vulnerable dependency
                            analysis_result = dep_agent.analyze(dependency)
                            
                            # Create DependencyCheckFinding records for each vulnerability
                            for vuln in dependency.get('vulnerabilities', []):
                                finding = DependencyCheckFinding(
                                    scan_id=scan_id,
                                    dependency_name=dependency.get('fileName', ''),
                                    dependency_version=dependency.get('version', ''),
                                    vulnerability_id=vuln.get('name', ''),
                                    vulnerability_name=vuln.get('name', ''),
                                    severity=vuln.get('severity', ''),
                                    cvss_score=float(vuln.get('cvssv3', {}).get('baseScore', 0)),
                                    description=vuln.get('description', ''),
                                    llm_exploitability=analysis_result.get('analysis', {}).get('exploitability', ''),
                                    llm_priority=analysis_result.get('analysis', {}).get('priority', ''),
                                    raw_data={
                                        'analysis': analysis_result.get('analysis', {}),
                                        'usage_patterns': analysis_result.get('context', {}).get('usage', {}),
                                        'exploitability': analysis_result.get('context', {}).get('exploitability', {})
                                    }
                                )
                                session.add(finding)
                            session.commit()
                            
                            if 'error' in analysis_result:
                                logger.error(f"Error in dependency analysis: {analysis_result['error']}")
                                dependency['llm_analysis'] = {"error": analysis_result['error']}
                            else:
                                dependency['llm_analysis'] = {
                                    "analysis": analysis_result.get("analysis", {}),
                                    "usage_patterns": analysis_result.get("context", {}).get("usage", {}),
                                    "exploitability": analysis_result.get("context", {}).get("exploitability", {})
                                }
                                logger.info(f"Successfully analyzed dependency {i}/{len(dependencies)}")
                        except Exception as e:
                            logger.error(f"Error enhancing dependency with LLM: {str(e)}")
                            dependency['llm_analysis'] = {"error": str(e)}
                    enhanced_dependencies.append(dependency)
                results['results']['dependencies'] = enhanced_dependencies
                logger.info("Completed LLM analysis of all dependencies")

        if session and scan_id:
            scan = session.query(Scan).filter_by(id=scan_id).first()
            if scan:
                scan.progress_percentage = 90
                scan.dependency_status = 'completed'  # Update status to completed
                session.commit()

        if 'success' in results and results['success']:
            save_dependency_results_to_cache(repo_path, results)
            
        return {
            'success': True,
            'results': results,
            'json_report': os.path.join(output_dir, "dependency-check-report.json"),
            'html_report': os.path.join(output_dir, "dependency-check-report.html"),
            'cached': False
        }
    except subprocess.CalledProcessError as e:
        if session and scan_id:
            scan = session.query(Scan).filter_by(id=scan_id).first()
            if scan:
                scan.status = 'failed'
                scan.dependency_status = 'failed'  # Update status to failed
                scan.error_message = f'Dependency-Check analysis failed: {str(e)}'
                session.commit()
        return {'error': f'Dependency-Check analysis failed: {str(e)}'}
    except Exception as e:
        if session and scan_id:
            scan = session.query(Scan).filter_by(id=scan_id).first()
            if scan:
                scan.status = 'failed'
                scan.dependency_status = 'failed'  # Update status to failed
                scan.error_message = f'Dependency-Check processing failed: {str(e)}'
                session.commit()
        return {'error': f'Dependency-Check processing failed: {str(e)}'}

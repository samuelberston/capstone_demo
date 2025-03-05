from flask import Flask, request, jsonify
import subprocess
import os
import tempfile
import shutil
import git
from pathlib import Path
import json
import uuid
from llm_reasoning import LLMReasoningEngine
import logging

app = Flask(__name__)

CODEQL_QUERIES_PATH = "/opt/security-scanner/codeql-queries"

# New persistent directory for storing analysis files
DATA_DIR = "/data"
os.makedirs(DATA_DIR, exist_ok=True)

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Add environment variable for LLM API key
LLM_API_KEY = os.environ.get('LLM_API_KEY', '')
LLM_MODEL = os.environ.get('LLM_MODEL', 'gpt-4')
LLM_API_BASE = os.environ.get('LLM_API_BASE', None)

# Initialize LLM reasoning engine if API key is provided
llm_engine = None
if LLM_API_KEY:
    llm_engine = LLMReasoningEngine(LLM_API_KEY, LLM_MODEL, LLM_API_BASE)
    logger.info(f"LLM reasoning engine initialized with model: {LLM_MODEL}")
else:
    logger.warning("LLM_API_KEY not provided. LLM reasoning will be disabled.")

def detect_all_languages(repo_path):
    """
    Return a list of all detected languages based on file extensions.
    """
    language_stats = {}
    
    # Common file extensions and their languages
    extensions = {
        '.py': 'python',
        '.js': 'javascript',
        '.ts': 'javascript',  # TypeScript files analyzed with JavaScript
        '.java': 'java',
        '.cpp': 'cpp',
        '.cc': 'cpp',
        '.c': 'cpp',
        '.cs': 'csharp',
        '.go': 'go',
        '.rb': 'ruby'
    }
    
    # Walk through the repository
    for root, _, files in os.walk(repo_path):
        if '.git' in root:
            # Skip .git directory
            continue
        
        for file in files:
            ext = os.path.splitext(file)[1].lower()
            if ext in extensions:
                lang = extensions[ext]
                language_stats[lang] = language_stats.get(lang, 0) + 1
    
    # Return all unique languages detected
    return list(language_stats.keys())

def get_query_suite_path(language, repo_url=None):
    """Get the path to the appropriate query suite for the specified language."""
    
    # Special handling for Juice Shop repository
    is_juice_shop = repo_url and 'juice-shop/juice-shop' in repo_url
    
    if is_juice_shop and language == 'javascript':
        # Use filtered critical rules for Juice Shop
        critical_rules = {
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
        
        # Create a temporary query suite file with only critical rules
        temp_suite = tempfile.NamedTemporaryFile(mode='w', suffix='.qls', delete=False)
        with temp_suite as f:
            f.write("- queries: .\n")
            for rule in critical_rules:
                f.write(f"  - include: {rule}\n")
        return temp_suite.name
    
    # Default query suites for other repositories/languages
    query_suites = {
        'python': f"{CODEQL_QUERIES_PATH}/python/ql/src/codeql-suites/python-security-and-quality.qls",
        'javascript': f"{CODEQL_QUERIES_PATH}/javascript/ql/src/codeql-suites/javascript-security-and-quality.qls",
        'java': f"{CODEQL_QUERIES_PATH}/java/ql/src/codeql-suites/java-security-and-quality.qls",
        'cpp': f"{CODEQL_QUERIES_PATH}/cpp/ql/src/codeql-suites/cpp-security-and-quality.qls",
        'csharp': f"{CODEQL_QUERIES_PATH}/csharp/ql/src/codeql-suites/csharp-security-and-quality.qls",
        'go': f"{CODEQL_QUERIES_PATH}/go/ql/src/codeql-suites/go-security-and-quality.qls",
        'ruby': f"{CODEQL_QUERIES_PATH}/ruby/ql/src/codeql-suites/ruby-security-and-quality.qls"
    }
    return query_suites.get(language)

def run_codeql_analysis(repo_path, language, repo_url=None):
    """
    Run CodeQL analysis on the repository for a single language
    and return simplified results including a reference to the
    persisted SARIF file.
    """
    with tempfile.TemporaryDirectory() as db_path:
        try:
            # Create CodeQL database
            subprocess.run([
                'codeql', 'database', 'create',
                f'{db_path}/db',
                f'--language={language}',
                '--source-root', repo_path
            ], check=True)

            # Get the appropriate query suite path - now always use the default suite
            query_suite = get_query_suite_path(language)
            if not query_suite:
                return {'error': f'No query suite found for language: {language}'}

            # Analyze the database
            results_path = f'{db_path}/results_{language}.sarif'
            subprocess.run([
                'codeql', 'database', 'analyze',
                f'{db_path}/db',
                '--format=sarif-latest',
                '-o', results_path,
                query_suite
            ], check=True)

            # Read and parse the results
            with open(results_path, 'r') as f:
                analysis_results = json.load(f)

            # Filter results for Juice Shop if needed
            results = analysis_results.get('runs', [{}])[0].get('results', [])
            if repo_url and 'juice-shop/juice-shop' in repo_url and language == 'javascript':
                critical_rules = {
                    'js/sql-injection',
                    'js/code-injection',
                    'js/command-line-injection',
                    'js/xss',
                    'js/hardcoded-credentials',
                    'js/jwt-missing-verification',
                    'js/prototype-pollution',
                    'js/unsafe-deserialization',
                    'js/sensitive-data-exposure',
                    'js/server-side-request-forgery',
                    'js/open-redirect'
                }
                results = [r for r in results if r.get('ruleId') in critical_rules]

            # Add LLM reasoning to findings if enabled
            if llm_engine and results:
                logger.info(f"Enhancing {len(results)} CodeQL findings with LLM reasoning")
                enhanced_results = []
                for finding in results:
                    try:
                        enhanced_finding = llm_engine.analyze_codeql_finding(finding, repo_path)
                        enhanced_results.append(enhanced_finding)
                    except Exception as e:
                        logger.error(f"Error enhancing finding with LLM: {str(e)}")
                        finding['llm_analysis'] = {"error": str(e)}
                        enhanced_results.append(finding)
                results = enhanced_results

            # Save a permanent copy of the SARIF file
            unique_filename = f"results_{language}_{uuid.uuid4().hex}.sarif"
            permanent_path = os.path.join(DATA_DIR, unique_filename)
            shutil.copy(results_path, permanent_path)

            simplified_results = {
                'language': language,
                'results': results,
                'saved_analysis_file': permanent_path
            }
            return simplified_results

        except subprocess.CalledProcessError as e:
            return {'error': f'CodeQL analysis failed for {language}: {str(e)}'}

def run_dependency_check(repo_path):
    """
    Run OWASP Dependency-Check on the repository and return results.
    """
    try:
        # Install dependencies based on project type
        if os.path.exists(os.path.join(repo_path, 'package.json')):
            logger.info("Detected Node.js project, installing dependencies...")
            subprocess.run(['npm', 'install', '--package-lock-only'], 
                         cwd=repo_path, check=True)
        
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

        # Create a unique output directory for this scan
        output_dir = os.path.join(DATA_DIR, f"depcheck_{uuid.uuid4().hex}")
        os.makedirs(output_dir, exist_ok=True)
        
        # Output files
        json_report = os.path.join(output_dir, "dependency-check-report.json")
        html_report = os.path.join(output_dir, "dependency-check-report.html")
        
        # Run dependency-check
        subprocess.run([
            'dependency-check',
            '--scan', repo_path,
            '--format', 'JSON',
            '--format', 'HTML',
            '--out', output_dir,
            '--enableExperimental'
        ], check=True)
        
        # Read and parse the JSON results
        with open(json_report, 'r') as f:
            results = json.load(f)
            
        # Add LLM reasoning to dependency findings if enabled
        if llm_engine and 'results' in results:
            dependencies = results.get('results', {}).get('dependencies', [])
            if dependencies:
                logger.info(f"Enhancing dependency findings with LLM reasoning")
                for dependency in dependencies:
                    if dependency.get('vulnerabilities'):
                        for vuln in dependency.get('vulnerabilities', []):
                            try:
                                # Create a simplified finding object for the LLM engine
                                finding = {
                                    'dependency_name': dependency.get('fileName', ''),
                                    'dependency_version': dependency.get('version', ''),
                                    'vulnerability_id': vuln.get('name', ''),
                                    'description': vuln.get('description', ''),
                                    'severity': vuln.get('severity', ''),
                                    'cvss_score': vuln.get('cvssv3', {}).get('baseScore', 0.0)
                                }
                                
                                # Enhance with LLM reasoning
                                enhanced_finding = llm_engine.analyze_dependency_finding(finding, repo_path)
                                
                                # Add the LLM analysis back to the original vulnerability
                                vuln['llm_analysis'] = enhanced_finding.get('llm_analysis', {})
                                
                            except Exception as e:
                                logger.error(f"Error enhancing dependency finding with LLM: {str(e)}")
                                vuln['llm_analysis'] = {"error": str(e)}
        
        return {
            'success': True,
            'results': results,
            'json_report': json_report,
            'html_report': html_report
        }
    except subprocess.CalledProcessError as e:
        return {'error': f'Dependency-Check analysis failed: {str(e)}'}
    except Exception as e:
        return {'error': f'Dependency-Check processing failed: {str(e)}'}

@app.route('/analyze', methods=['POST'])
def analyze_repo():
    data = request.get_json()
    if not data or 'github_url' not in data:
        return jsonify({'error': 'GitHub URL is required'}), 400

    github_url = data['github_url']
    
    # Ensure the URL uses HTTPS and ends with .git
    if not github_url.endswith('.git'):
        github_url = f"{github_url}.git"
    
    with tempfile.TemporaryDirectory() as temp_dir:
        try:
            # Clone repository
            git.Repo.clone_from(
                github_url,
                temp_dir,
                env={'GIT_TERMINAL_PROMPT': '0'},
                config='http.sslVerify=true',
                allow_unsafe_options=True
            )
            
            # Detect all languages
            detected_languages = detect_all_languages(temp_dir)
            
            if not detected_languages:
                # Default to python if no recognized extensions found
                detected_languages = ['python']

            combined_results = []
            saved_files = []

            # Run CodeQL analysis for each detected language
            for lang in detected_languages:
                analysis = run_codeql_analysis(temp_dir, lang, github_url)
                
                # If an error occurs for a language, return immediately
                if 'error' in analysis:
                    return jsonify({
                        'error': analysis['error']
                    }), 400

                # Accumulate results
                combined_results.extend(analysis.get('results', []))
                if 'saved_analysis_file' in analysis:
                    saved_files.append(analysis['saved_analysis_file'])
            
            # Run OWASP Dependency-Check
            dependency_check_results = run_dependency_check(temp_dir)
            
            # Check for errors in dependency check
            if 'error' in dependency_check_results:
                return jsonify({
                    'error': dependency_check_results['error']
                }), 400

            return jsonify({
                'repository': github_url,
                'detected_languages': detected_languages,
                'analysis_results': {
                    'results': combined_results,
                    'saved_analysis_files': saved_files
                },
                'dependency_check': {
                    'results': dependency_check_results.get('results', {}),
                    'reports': {
                        'json': dependency_check_results.get('json_report'),
                        'html': dependency_check_results.get('html_report')
                    }
                }
            })

        except git.GitCommandError as e:
            return jsonify({'error': f'Failed to clone repository: {str(e)}'}), 400
        except Exception as e:
            return jsonify({'error': f'Analysis failed: {str(e)}'}), 500

@app.route('/health', methods=['GET'])
def health_check():
    """Simple health check endpoint."""
    return jsonify({'status': 'healthy'}), 200

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000) 
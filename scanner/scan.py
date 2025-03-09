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

# Use relative imports instead of absolute
from .agents.code_agent import CodeAnalysisAgent
from .agents.dependency_agent import DependencyAnalysisAgent

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Update paths to be absolute
CODEQL_QUERIES_PATH = "/opt/security-scanner/codeql-queries"
DATA_DIR = "/opt/security-scanner/data"
os.makedirs(DATA_DIR, exist_ok=True)

# Add cache directory with absolute path
CACHE_DIR = os.path.join(DATA_DIR, "cache")
os.makedirs(CACHE_DIR, exist_ok=True)

def detect_all_languages(repo_path):
    """
    Return a list of all detected languages based on file extensions.
    """
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
    
    for root, _, files in os.walk(repo_path):
        if '.git' in root:
            continue
        
        for file in files:
            ext = os.path.splitext(file)[1].lower()
            if ext in extensions:
                lang = extensions[ext]
                language_stats[lang] = language_stats.get(lang, 0) + 1
    
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

def run_codeql_analysis(repo_path, language, repo_url=None):
    """
    Run CodeQL analysis on the repository for a single language
    and return simplified results including a reference to the
    persisted SARIF file.
    """
    # Check cache first
    cached_results = get_cached_results(repo_path, language)
    if cached_results:
        return cached_results

    with tempfile.TemporaryDirectory() as db_path:
        try:
            # Initialize the code analysis agent
            code_agent = CodeAnalysisAgent(repo_path=repo_path)
            
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
                    'js/open-redirect',
                    'js/request-forgery',
                    'js/path-injection',
                    'js/client-side-unvalidated-url-redirection',
                    'js/prototype-polluting-assignment',
                    'js/insecure-randomness'
                    'js/insufficient-password-hash',
                    'js/missing-token-validation'
                }
                results = [r for r in results if r.get('ruleId') in critical_rules]

            # Add LLM reasoning to findings
            if results:
                logger.info(f"Enhancing {len(results)} CodeQL findings with LLM reasoning")
                enhanced_results = []
                for finding in results:
                    try:
                        # Use the code analysis agent to analyze each finding
                        analysis_result = code_agent.analyze(finding)
                        if 'error' in analysis_result:
                            logger.error(f"Error in LLM analysis: {analysis_result['error']}")
                            finding['llm_analysis'] = {"error": analysis_result['error']}
                        else:
                            finding['llm_analysis'] = {
                                "analysis": analysis_result.get("analysis", ""),
                                "code_context": analysis_result.get("code_context", "")
                            }
                        enhanced_results.append(finding)
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

            # Cache the results before returning
            save_to_cache(repo_path, language, simplified_results)
            return simplified_results

        except subprocess.CalledProcessError as e:
            return {'error': f'CodeQL analysis failed for {language}: {str(e)}'}

def run_dependency_check(repo_path):
    """
    Run OWASP Dependency-Check on the repository and return results.
    """
    try:
        # Initialize the dependency analysis agent
        dep_agent = DependencyAnalysisAgent(repo_path=repo_path)
        
        logger.info(f"Starting dependency check analysis for repo: {repo_path}")
        
        # Install dependencies based on project type
        if os.path.exists(os.path.join(repo_path, 'package.json')):
            logger.info("Detected Node.js project, installing dependencies...")
            subprocess.run(['npm', 'install', '--package-lock-only'], 
                         cwd=repo_path, check=True, capture_output=True)
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

        # Create a unique output directory for this scan
        output_dir = os.path.join(DATA_DIR, f"depcheck_{uuid.uuid4().hex}")
        logger.info(f"Created output directory: {output_dir}")
        
        # Run dependency-check with verbose output
        logger.info("Starting OWASP Dependency Check scan...")
        result = subprocess.run([
            'dependency-check',
            '--scan', repo_path,
            '--format', 'JSON',
            '--format', 'HTML',
            '--out', output_dir,
            '--enableExperimental',
            '--log', os.path.join(output_dir, 'dependency-check.log')  # Add specific log file
        ], check=True, capture_output=True)
        
        logger.info(f"Dependency check completed. Output saved to: {output_dir}")
        if result.stderr:
            logger.warning(f"Dependency check stderr: {result.stderr.decode()}")
        
        # Read and parse the JSON results
        with open(os.path.join(output_dir, "dependency-check-report.json"), 'r') as f:
            results = json.load(f)
              
        # TODO: Filter out low severity dependencies for llm analysis      
        # Add LLM reasoning to dependency findings
        if 'results' in results:
            dependencies = results.get('results', {}).get('dependencies', [])
            if dependencies:
                logger.info(f"Enhancing dependency findings with LLM reasoning")
                enhanced_dependencies = []
                for dependency in dependencies:
                    if dependency.get('vulnerabilities'):
                        try:
                            # Use the dependency analysis agent to analyze each vulnerable dependency
                            analysis_result = dep_agent.analyze(dependency)
                            if 'error' in analysis_result:
                                logger.error(f"Error in dependency analysis: {analysis_result['error']}")
                                dependency['llm_analysis'] = {"error": analysis_result['error']}
                            else:
                                dependency['llm_analysis'] = {
                                    "analysis": analysis_result.get("analysis", {}),
                                    "usage_patterns": analysis_result.get("context", {}).get("usage", {}),
                                    "exploitability": analysis_result.get("context", {}).get("exploitability", {})
                                }
                        except Exception as e:
                            logger.error(f"Error enhancing dependency with LLM: {str(e)}")
                            dependency['llm_analysis'] = {"error": str(e)}
                    enhanced_dependencies.append(dependency)
                results['results']['dependencies'] = enhanced_dependencies

        return {
            'success': True,
            'results': results,
            'json_report': os.path.join(output_dir, "dependency-check-report.json"),
            'html_report': os.path.join(output_dir, "dependency-check-report.html")
        }
    except subprocess.CalledProcessError as e:
        return {'error': f'Dependency-Check analysis failed: {str(e)}'}
    except Exception as e:
        return {'error': f'Dependency-Check processing failed: {str(e)}'}

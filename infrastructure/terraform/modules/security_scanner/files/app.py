from flask import Flask, request, jsonify
import subprocess
import os
import tempfile
import shutil
import git
from pathlib import Path
import json
import uuid

app = Flask(__name__)

CODEQL_QUERIES_PATH = "/opt/security-scanner/codeql-queries"

# New persistent directory for storing analysis files
DATA_DIR = "/data"
os.makedirs(DATA_DIR, exist_ok=True)

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

            return jsonify({
                'repository': github_url,
                'detected_languages': detected_languages,
                'analysis_results': {
                    'results': combined_results,
                    'saved_analysis_files': saved_files
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
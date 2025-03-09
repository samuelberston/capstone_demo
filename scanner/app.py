from flask import Flask, request, jsonify
import git
import tempfile
import logging
import os
from .scan import detect_all_languages, run_codeql_analysis, run_dependency_check

app = Flask(__name__)

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

@app.route('/analyze', methods=['POST'])
def analyze_repo():
    data = request.get_json()
    if not data or 'github_url' not in data:
        return jsonify({'error': 'GitHub URL is required'}), 400

    github_url = data['github_url']
    
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
                detected_languages = ['python']

            combined_results = []
            saved_files = []

            # Run CodeQL analysis for each detected language
            for lang in detected_languages:
                analysis = run_codeql_analysis(temp_dir, lang, github_url)
                
                if 'error' in analysis:
                    return jsonify({'error': analysis['error']}), 400

                combined_results.extend(analysis.get('results', []))
                if 'saved_analysis_file' in analysis:
                    saved_files.append(analysis['saved_analysis_file'])
            
            # Run OWASP Dependency-Check
            dependency_check_results = run_dependency_check(temp_dir)
            
            if 'error' in dependency_check_results:
                return jsonify({'error': dependency_check_results['error']}), 400

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
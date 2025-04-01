import os
import logging
import subprocess
from scanner.scan import run_dependency_check

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def test_dependency_check(repo_path):
    """
    Test dependency check on a local repository.
    Args:
        repo_path (str): Path to the repository to analyze
    """
    logger.info(f"Starting dependency check test on: {repo_path}")
    
    if not os.path.exists(repo_path):
        logger.error(f"Repository path does not exist: {repo_path}")
        return
    
    try:
        # First, let's check if we need to install dependencies
        if os.path.exists(os.path.join(repo_path, 'package.json')):
            logger.info("Found package.json, checking if node_modules exists...")
            if not os.path.exists(os.path.join(repo_path, 'node_modules')):
                logger.info("node_modules not found, installing dependencies...")
                try:
                    # Run npm install with output streaming
                    process = subprocess.Popen(
                        ['npm', 'install', '--no-audit'],
                        cwd=repo_path,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        text=True,
                        bufsize=1,
                        universal_newlines=True
                    )
                    
                    # Stream the output
                    while True:
                        output = process.stdout.readline()
                        if output == '' and process.poll() is not None:
                            break
                        if output:
                            logger.info(f"npm: {output.strip()}")
                    
                    # Check for errors
                    if process.returncode != 0:
                        error = process.stderr.read()
                        logger.error(f"npm install failed: {error}")
                        return
                    
                    logger.info("npm install completed successfully")
                except Exception as e:
                    logger.error(f"Error during npm install: {str(e)}")
                    return
            else:
                logger.info("node_modules already exists, skipping npm install")

        # Now run the dependency check
        logger.info("Starting OWASP Dependency Check...")
        results = run_dependency_check(repo_path)
        
        if 'error' in results:
            logger.error(f"Dependency check failed: {results['error']}")
            return
        
        logger.info("Dependency check completed successfully")
        logger.info(f"Results saved to: {results.get('json_report', 'N/A')}")
        
        # Print summary of findings
        if 'results' in results and 'results' in results['results']:
            dependencies = results['results']['results'].get('dependencies', [])
            logger.info(f"Found {len(dependencies)} dependencies")
            
            # Count vulnerabilities by severity
            vuln_counts = {'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}
            for dep in dependencies:
                for vuln in dep.get('vulnerabilities', []):
                    severity = vuln.get('severity', 'UNKNOWN')
                    vuln_counts[severity] = vuln_counts.get(severity, 0) + 1
            
            logger.info(f"Vulnerability summary: {vuln_counts['HIGH']} High, {vuln_counts['MEDIUM']} Medium, {vuln_counts['LOW']} Low")
        
    except Exception as e:
        logger.error(f"Error during dependency check: {str(e)}", exc_info=True)

if __name__ == "__main__":
    # Use the existing juice-shop directory
    REPO_PATH = "juice-shop"
    test_dependency_check(REPO_PATH) 
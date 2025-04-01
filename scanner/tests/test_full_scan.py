import os
import logging
from scanner.scan import run_dependency_check, run_codeql_analysis
from scanner.agents.code_agent import CodeAnalysisAgent

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def test_full_scan(repo_path):
    """
    Test both dependency check and LLM analysis on a local repository.
    Args:
        repo_path (str): Path to the repository to analyze
    """
    logger.info(f"Starting full security scan test on: {repo_path}")
    
    if not os.path.exists(repo_path):
        logger.error(f"Repository path does not exist: {repo_path}")
        return
    
    try:
        # Step 1: Run dependency check
        logger.info("Step 1: Running dependency check...")
        dep_results = run_dependency_check(repo_path)
        
        if 'error' in dep_results:
            logger.error(f"Dependency check failed: {dep_results['error']}")
            return
        
        logger.info("Dependency check completed successfully")
        
        # Step 2: Run CodeQL analysis for each detected language
        logger.info("Step 2: Running CodeQL analysis...")
        codeql_results = {}
        
        # For this test, we'll focus on JavaScript since it's a Node.js project
        js_results = run_codeql_analysis(repo_path, "javascript")
        if 'error' in js_results:
            logger.error(f"CodeQL analysis failed: {js_results['error']}")
            return
            
        codeql_results['javascript'] = js_results
        logger.info("CodeQL analysis completed successfully")
        
        # Step 3: Run LLM analysis
        logger.info("Step 3: Running LLM analysis...")
        code_agent = CodeAnalysisAgent(repo_path)
        
        # Prepare context for LLM analysis
        context = {
            'dependency_results': dep_results,
            'codeql_results': codeql_results,
            'repo_path': repo_path
        }
        
        # Run LLM analysis
        llm_results = code_agent.analyze(context)
        
        if 'error' in llm_results:
            logger.error(f"LLM analysis failed: {llm_results['error']}")
            return
            
        logger.info("LLM analysis completed successfully")
        
        # Print summary of all findings
        logger.info("\n=== Scan Summary ===")
        
        # Dependency findings
        if 'results' in dep_results and 'results' in dep_results['results']:
            dependencies = dep_results['results']['results'].get('dependencies', [])
            vuln_counts = {'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}
            for dep in dependencies:
                for vuln in dep.get('vulnerabilities', []):
                    severity = vuln.get('severity', 'UNKNOWN')
                    vuln_counts[severity] = vuln_counts.get(severity, 0) + 1
            logger.info(f"Dependency Vulnerabilities: {vuln_counts['HIGH']} High, {vuln_counts['MEDIUM']} Medium, {vuln_counts['LOW']} Low")
        
        # CodeQL findings
        for lang, results in codeql_results.items():
            if 'results' in results:
                findings = results['results'].get('findings', [])
                logger.info(f"CodeQL Findings ({lang}): {len(findings)} issues found")
        
        # LLM findings
        if 'findings' in llm_results:
            logger.info(f"LLM Analysis Findings: {len(llm_results['findings'])} issues identified")
        
    except Exception as e:
        logger.error(f"Error during full scan: {str(e)}", exc_info=True)

if __name__ == "__main__":
    # Use the existing juice-shop directory
    REPO_PATH = "juice-shop"
    test_full_scan(REPO_PATH) 
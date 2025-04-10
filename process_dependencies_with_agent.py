import json
import os
import logging
import argparse
from pathlib import Path
import sys
import subprocess
import uuid
import shutil
from langchain_core.messages import BaseMessage
# --- Typing import ---
from typing import Any

# --- Configuration ---
# Use environment variable for data directory or default
BASE_DIR = Path(__file__).parent.resolve()
DATA_DIR = os.getenv('SECURITY_SCANNER_DATA', BASE_DIR / "data" / "local_depcheck")
os.makedirs(DATA_DIR, exist_ok=True)
# --- End Configuration ---

# Add the project root to the Python path
project_root = Path(__file__).parent.resolve()
sys.path.insert(0, str(project_root))

try:
    # Attempt to import the agent
    from scanner.agents.dependency import DependencyAnalysisAgent
    # Potential future dependency if UsageAnalyzer is separate
    # from scanner.agents.usage import UsageAnalyzer
except ImportError as e:
    print(f"Error: Could not import DependencyAnalysisAgent: {e}")
    print("Ensure this script is run from the project root directory ('demo')")
    print(f"Project Root added to sys.path: {project_root}")
    print(f"Current sys.path: {sys.path}")
    sys.exit(1)

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# --- Environment Variable Checks ---
if not os.getenv('OPENAI_API_KEY'):
    logger.error("STOPPING: OPENAI_API_KEY environment variable not set.")
    print("\nPlease set the OPENAI_API_KEY environment variable before running.")
    print("Example: export OPENAI_API_KEY='your_api_key_here'")
    sys.exit(1)

NVD_API_KEY = os.getenv('NVD_API_KEY')
if not NVD_API_KEY:
    logger.warning("NVD_API_KEY environment variable not set. Dependency-Check will be slower.")
else:
    logger.info("Using NVD_API_KEY for Dependency-Check.")
# --- End Environment Variable Checks ---


def check_command_exists(command: str) -> bool:
    """Check if a command exists on the system path."""
    return shutil.which(command) is not None

def run_npm_install(repo_path: str):
    """Install Node.js dependencies using npm ci or npm install."""
    logger.info(f"Checking for Node.js dependencies in {repo_path}...")
    package_json_path = os.path.join(repo_path, 'package.json')
    package_lock_path = os.path.join(repo_path, 'package-lock.json')

    if not os.path.exists(package_json_path):
        logger.info("No package.json found. Skipping npm install.")
        return

    if not check_command_exists('npm'):
        logger.error("STOPPING: 'npm' command not found in PATH.")
        print("Please install Node.js and npm.")
        sys.exit(1)

    if os.path.exists(package_lock_path):
        logger.info("Found package-lock.json, running 'npm ci'...")
        cmd = ['npm', 'ci']
    else:
        logger.warning("No package-lock.json found, running 'npm install'. This might take longer.")
        # Using --no-audit as in scan.py for speed
        cmd = ['npm', 'install', '--no-audit']

    try:
        result = subprocess.run(
            cmd,
            cwd=repo_path,
            capture_output=True,
            text=True,
            check=True,
            timeout=600 # Add a timeout (10 minutes)
        )
        logger.info("'npm' command completed successfully.")
        logger.debug(f"npm stdout:\n{result.stdout}")
    except subprocess.CalledProcessError as e:
        logger.error(f"'npm' command failed with return code {e.returncode}.")
        logger.error(f"npm stderr:\n{e.stderr}")
        logger.error(f"npm stdout:\n{e.stdout}")
        print(f"\nError running '{' '.join(cmd)}'. Check the logs above.")
        sys.exit(1)
    except subprocess.TimeoutExpired:
         logger.error(f"'npm' command timed out after 10 minutes.")
         print("\nError: npm install/ci took too long.")
         sys.exit(1)
    except Exception as e:
        logger.error(f"An unexpected error occurred during npm install: {e}", exc_info=True)
        sys.exit(1)

def run_dep_check_cli(repo_path: str, output_dir: str) -> str:
    """Run the dependency-check CLI tool."""
    logger.info("Running OWASP Dependency-Check CLI...")
    json_report_path = os.path.join(output_dir, "dependency-check-report.json")

    if not check_command_exists('dependency-check'):
        logger.error("STOPPING: 'dependency-check' command not found in PATH.")
        print("Please install the OWASP Dependency-Check CLI tool.")
        print("See: https://owasp.org/www-project-dependency-check/#command-line")
        sys.exit(1)

    cmd = [
        'dependency-check',
        '--scan', repo_path,
        '--format', 'JSON', # Only need JSON for this script
        '--out', output_dir,
        '--enableExperimental', # Recommended in scan.py
        # '--failOnCVSS', '7' # Optional: fail script if severe vulns found
    ]

    if NVD_API_KEY:
        cmd.extend(['--nvdApiKey', NVD_API_KEY])

    logger.info(f"Executing command: {' '.join(cmd)}")
    try:
        # Run dependency-check (can take a long time, especially the first run)
        # Increase timeout significantly
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            check=False, # Don't exit immediately on failure, check output
            timeout=1800 # 30 minutes timeout
        )

        logger.info(f"Dependency-Check CLI finished with return code {result.returncode}")
        logger.debug(f"Dependency-Check stdout:\n{result.stdout}")
        if result.returncode != 0:
             logger.warning(f"Dependency-Check CLI returned non-zero status.")
             logger.warning(f"Dependency-Check stderr:\n{result.stderr}")
             # Check if the report was still generated
             if not os.path.exists(json_report_path):
                  logger.error("STOPPING: Dependency-Check failed and JSON report was not generated.")
                  print("\nError running Dependency-Check. Check logs.")
                  sys.exit(1)
             else:
                  logger.warning("JSON report found despite non-zero exit code. Proceeding with analysis.")

        if not os.path.exists(json_report_path):
            logger.error(f"STOPPING: Expected JSON report not found at {json_report_path}")
            print("\nError: Dependency-Check finished but did not create the JSON report.")
            sys.exit(1)

        logger.info(f"Dependency-Check JSON report generated at: {json_report_path}")
        return json_report_path

    except subprocess.TimeoutExpired:
        logger.error("STOPPING: Dependency-Check CLI timed out after 30 minutes.")
        print("\nError: Dependency-Check took too long to complete.")
        sys.exit(1)
    except Exception as e:
        logger.error(f"An unexpected error occurred during Dependency-Check execution: {e}", exc_info=True)
        sys.exit(1)

def parse_agent_json(json_string: str) -> dict:
    """Safely parse the JSON string from the agent."""
    # Reuse the function from the other script if needed, or implement basic parsing
    try:
        # Basic cleanup - remove markdown fences if present
        if isinstance(json_string, str):
            if json_string.startswith("```json"):
                json_string = json_string[7:]
            if json_string.endswith("```"):
                json_string = json_string[:-3]
            json_string = json_string.strip()
            return json.loads(json_string)
        elif isinstance(json_string, dict): # Agent might return dict directly
            return json_string
        else:
             logger.warning(f"Unexpected type for agent JSON: {type(json_string)}")
             return {}
    except json.JSONDecodeError as e:
        logger.error(f"Failed to parse agent JSON: {e}")
        logger.error(f"Problematic JSON string:\n---\n{json_string}\n---")
        return {}
    except Exception as e:
        logger.error(f"Unexpected error parsing agent JSON: {e}", exc_info=True)
        return {}

# --- Add Helper Function ---
def make_json_serializable(data: Any) -> Any:
    """Recursively converts BaseMessage objects and sets in nested data structures to serializable types."""
    if isinstance(data, dict):
        return {k: make_json_serializable(v) for k, v in data.items()}
    elif isinstance(data, list):
        return [make_json_serializable(item) for item in data]
    # --- Add handling for sets ---
    elif isinstance(data, set):
        # Convert sets to lists
        return [make_json_serializable(item) for item in data] 
    # --- End handling for sets ---
    elif isinstance(data, BaseMessage):
        return data.content # Convert BaseMessage to its string content
    else:
        return data # Return other types as is
# --- End Helper Function ---


def transform_dependency_finding(dep_report_item: dict, agent_output: dict, index: int, scan_id: int = 1) -> list[dict] | None:
    """
    Transforms a dependency report item and its agent analysis into the frontend format.
    Returns a list of findings, one for each vulnerability in the dependency.
    """
    base_file_name = dep_report_item.get('fileName', 'Unknown Dependency')
    logger.info(f"Transforming findings for dependency {index}: {base_file_name}")

    if 'error' in agent_output:
        logger.error(f"Agent returned an error for dependency {base_file_name}: {agent_output['error']}")
        # Still create basic findings from report if agent failed
        agent_analysis_parsed = {"error": agent_output['error']}
        agent_usage_patterns = {}
        agent_exploitability_context = {}
    else:
        # Safely parse/access agent results
        agent_analysis_parsed = parse_agent_json(agent_output.get('analysis', {})) # analysis part
        agent_usage_patterns = agent_output.get('context', {}).get('usage', {}) # usage context
        agent_exploitability_context = agent_output.get('context', {}).get('exploitability', {}) # exploitability context


    vulnerabilities = dep_report_item.get('vulnerabilities', [])
    if not vulnerabilities:
        logger.info(f"No vulnerabilities found for {base_file_name}, skipping.")
        return []

    frontend_findings = []
    vuln_index = 0
    for vuln in vulnerabilities:
        vuln_index += 1
        logger.info(f"  - Processing vulnerability {vuln_index}/{len(vulnerabilities)}: {vuln.get('name', 'N/A')}")

        # Extract CVSS score safely
        cvss_score = 0.0
        if 'cvssv3' in vuln and isinstance(vuln['cvssv3'], dict):
            cvss_score = float(vuln['cvssv3'].get('baseScore', 0.0))
        elif 'cvssv2' in vuln and isinstance(vuln['cvssv2'], dict):
             cvss_score = float(vuln['cvssv2'].get('score', 0.0)) # Fallback to CVSSv2

        # Map fields from report and agent analysis
        finding = {
            "id": f"{index}-{vuln_index}", # Create a unique ID
            "scan_id": scan_id,
            "dependency_name": dep_report_item.get('filePath', base_file_name), # Use filePath if available
            "dependency_version": dep_report_item.get('version', 'N/A'),
            "vulnerability_id": vuln.get('name', 'N/A'), # CVE ID or similar
            "vulnerability_name": vuln.get('name', 'N/A'), # Can be improved if report has a better name field
            "severity": vuln.get('severity', 'UNKNOWN').upper(),
            "cvss_score": cvss_score,
            "description": vuln.get('description', 'No description provided.'),
            # --- LLM Fields from Agent ---
            "llm_exploitability": agent_analysis_parsed.get('exploitability', 'N/A'),
            "llm_priority": agent_analysis_parsed.get('priority', 'N/A'),
            "code_context": agent_usage_patterns.get('code_snippet', 'Context not analyzed or found.'), # Example from agent's potential output
            "affected_files": agent_usage_patterns.get('files', []), # Example
             # Analysis object (structured similarly to CodeQLFinding for consistency)
            "analysis": {
                "description": agent_analysis_parsed.get('vulnerability_description', vuln.get('description', 'N/A')), # Agent might provide better description
                "dataFlow": agent_exploitability_context.get('attack_vector', 'N/A'), # Map context if available
                "recommendations": agent_analysis_parsed.get('recommendations', []),
                "vulnerableCode": agent_usage_patterns.get('code_snippet', None), # If context is code
             },
             # --- End LLM Fields ---
             "raw_data": {
                "original_dependency_report": dep_report_item,
                "original_vulnerability_report": vuln,
                "agent_analysis_full": make_json_serializable(agent_output)
             }
        }
        frontend_findings.append(finding)

    logger.info(f"Successfully transformed {len(frontend_findings)} findings for dependency {base_file_name}")
    return frontend_findings


def main(repo_path: str, output_path: str):
    """Orchestrates dependency installation, scanning, agent analysis, and output generation."""
    logger.info(f"Starting dependency analysis process for repository: {repo_path}")
    repo_path_abs = os.path.abspath(repo_path)
    output_path_abs = os.path.abspath(output_path)

    # --- Conditionally skip install ---
    if not args.skip_install:
        # 1. Install Dependencies (if applicable)
        # Only run for Node.js projects for now, extend as needed
        if os.path.exists(os.path.join(repo_path_abs, 'package.json')):
             run_npm_install(repo_path_abs)
        else:
             logger.info("No package.json found, skipping dependency installation step (--skip-install assumed)." if args.skip_install else "No package.json found, assuming dependencies are handled externally or not needed.")
    else:
        logger.info("--skip-install flag provided. Skipping npm install step.")

    # --- Conditionally skip scan or use existing report ---
    if not args.skip_scan:
        # 2. Run Dependency-Check CLI
        # Create a unique directory for this run's output
        depcheck_output_dir = os.path.join(DATA_DIR, f"depcheck_run_{uuid.uuid4().hex}")
        os.makedirs(depcheck_output_dir, exist_ok=True)
        logger.info(f"Dependency-Check output will be stored in: {depcheck_output_dir}")
        json_report_path = run_dep_check_cli(repo_path_abs, depcheck_output_dir)
    else:
        logger.info("--skip-scan flag provided. Attempting to use existing report.")
        if not args.report_path:
            logger.error("STOPPING: --skip-scan requires --report-path to be specified.")
            sys.exit(1)
        if not os.path.exists(args.report_path):
            logger.error(f"STOPPING: Specified report file not found: {args.report_path}")
            sys.exit(1)
        json_report_path = os.path.abspath(args.report_path)
        logger.info(f"Using existing report file: {json_report_path}")

    # 3. Load Dependency-Check Report
    logger.info(f"Loading Dependency-Check JSON report from: {json_report_path}")
    try:
        with open(json_report_path, 'r') as f:
            dep_check_results = json.load(f)
    except json.JSONDecodeError:
        logger.error(f"STOPPING: Failed to parse JSON report: {json_report_path}")
        sys.exit(1)
    except Exception as e:
         logger.error(f"STOPPING: Error reading report file {json_report_path}: {e}")
         sys.exit(1)

    # 4. Initialize Agent
    logger.info("Initializing DependencyAnalysisAgent...")
    try:
        # Pass repo_path for potential context analysis within the agent
        agent = DependencyAnalysisAgent(repo_path=repo_path_abs)
    except Exception as e:
         logger.error(f"STOPPING: Failed to initialize DependencyAnalysisAgent: {e}", exc_info=True)
         sys.exit(1)

    # 5. Process Vulnerable Dependencies with Agent
    all_transformed_findings = []
    dependencies = dep_check_results.get('dependencies', [])
    logger.info(f"Found {len(dependencies)} dependencies in the report.")

    vulnerable_deps_count = sum(1 for dep in dependencies if dep.get('vulnerabilities'))
    logger.info(f"Processing {vulnerable_deps_count} dependencies with vulnerabilities...")

    processed_dep_count = 0
    total_findings_processed = 0
    first_finding_written = True # Flag to manage comma placement

    try:
        with open(output_path_abs, 'w') as outfile:
            outfile.write("[\n") # Start the JSON array

            for i, dep in enumerate(dependencies):
                if dep.get('vulnerabilities'):
                    processed_dep_count += 1
                    dep_name = dep.get('fileName', f'dependency_{i+1}')
                    logger.info(f"--- Analyzing Dependency {processed_dep_count}/{vulnerable_deps_count}: {dep_name} ---")
                    try:
                        # Call the agent's analyze method
                        agent_result = agent.analyze(dep)

                        # Check if the agent skipped this dependency due to missing name
                        if agent_result.get("skipped"):
                             logger.warning(f"Agent skipped dependency {dep_name} due to missing fileName.")
                             continue # Skip to the next dependency

                        # Transform the result(s)
                        transformed_findings_list = transform_dependency_finding(dep, agent_result, index=i+1)

                        if transformed_findings_list:
                            for finding_data in transformed_findings_list:
                                if not first_finding_written:
                                    outfile.write(",\n") # Add comma before the next finding
                                json.dump(finding_data, outfile, indent=4) # Write the finding
                                first_finding_written = False
                                total_findings_processed += 1
                                logger.info(f"Saved finding {finding_data.get('id', 'N/A')} ({finding_data.get('vulnerability_id')}) for {dep_name}")
                        else:
                             logger.warning(f"No findings generated for dependency {dep_name} after transformation.")

                    except Exception as e:
                        logger.error(f"Error processing dependency {dep_name} with agent: {e}", exc_info=True)
                        # Decide if you want to write a placeholder error finding here

            outfile.write("\n]\n") # Close the JSON array

        logger.info(f"Agent analysis complete. Total transformed findings saved: {total_findings_processed}")
        logger.info(f"Final results saved to: {output_path_abs}")
        logger.info("Processing complete.")

    except IOError as e:
         logger.error(f"Error writing to output file {output_path_abs} during processing: {e}")
         # Attempt to close the JSON array gracefully
         try:
             with open(output_path_abs, 'a') as outfile:
                 if not first_finding_written: # Check if anything was written before adding newline
                      outfile.write("\n")
                 outfile.write("]\n")
             logger.info(f"Attempted to close JSON array in {output_path_abs} after IO error.")
         except IOError:
             logger.error(f"Could not write closing bracket to {output_path_abs} after IO error.")
         sys.exit(1)
    except Exception as e:
        logger.error(f"An unexpected error occurred during processing: {e}", exc_info=True)
        # Attempt to close the JSON array gracefully
        try:
             with open(output_path_abs, 'a') as outfile:
                 if not first_finding_written:
                     outfile.write("\n")
                 outfile.write("]\n")
             logger.info(f"Attempted to close JSON array in {output_path_abs} after error.")
        except IOError:
            logger.error(f"Could not write closing bracket to {output_path_abs} after error.")
        sys.exit(1)

    # Handle case where no vulnerable dependencies were found or processed
    if first_finding_written: # Means no findings were ever written
        try:
             with open(output_path_abs, 'w') as f: # Overwrite if completely empty
                 f.write("[]")
             logger.info("No findings were processed. Saved empty array.")
        except IOError as e:
            logger.error(f"Error writing empty output file {output_path_abs}: {e}")

    # 7. Cleanup (Optional)
    # Consider removing the depcheck_output_dir if not needed and not skipping scan
    # shutil.rmtree(depcheck_output_dir)
    # logger.info(f"Cleaned up temporary directory: {depcheck_output_dir}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Run Dependency-Check, analyze results with DependencyAnalysisAgent, and transform findings.")
    parser.add_argument("--repo-path", required=True, help="Path to the root of the repository to scan (needed for agent context even if skipping scan)." ) # Repo path still needed for agent context
    parser.add_argument("--output-path", required=True, help="Path to save the transformed JSON output file.")
    # --- Add new optional arguments ---
    parser.add_argument("--skip-install", action='store_true', help="Skip the 'npm install/ci' step.")
    parser.add_argument("--skip-scan", action='store_true', help="Skip running the 'dependency-check' CLI scan.")
    parser.add_argument("--report-path", help="Path to an existing dependency-check JSON report file (required if --skip-scan is used).")
    # --- End new arguments ---
    args = parser.parse_args()

    # Basic path validation
    if not os.path.isdir(args.repo_path):
         print(f"Error: Repository path not found or not a directory: {args.repo_path}")
         sys.exit(1)

    # Ensure output directory exists
    output_dir = os.path.dirname(args.output_path)
    if output_dir: # Handle case where output is in current dir
         os.makedirs(output_dir, exist_ok=True)

    main(args.repo_path, args.output_path)

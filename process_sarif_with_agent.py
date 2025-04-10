import json
import os
import logging
import argparse
from pathlib import Path
import sys

# Add the project root to the Python path to find the scanner module
project_root = Path(__file__).parent.resolve()
sys.path.insert(0, str(project_root))

try:
    from scanner.agents.code_agent import CodeAnalysisAgent
except ImportError:
    print("Error: Could not import CodeAnalysisAgent.")
    print("Ensure this script is run from the project root directory")
    print(f"Project Root added to sys.path: {project_root}")
    print(f"Current sys.path: {sys.path}")
    sys.exit(1)


# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Ensure OPENAI_API_KEY is set
if not os.getenv('OPENAI_API_KEY'):
    logger.error("Error: OPENAI_API_KEY environment variable not set.")
    print("\nPlease set the OPENAI_API_KEY environment variable before running.")
    print("Example: export OPENAI_API_KEY='your_api_key_here'")
    sys.exit(1)


def parse_agent_json(json_string: str) -> dict:
    """Safely parse the JSON string from the agent, removing potential markdown backticks."""
    try:
        # Remove potential markdown fences
        if json_string.startswith("```json"):
            json_string = json_string[7:]
        if json_string.endswith("```"):
            json_string = json_string[:-3]
        json_string = json_string.strip()
        return json.loads(json_string)
    except json.JSONDecodeError as e:
        logger.error(f"Failed to parse agent JSON: {e}")
        logger.error(f"Problematic JSON string:\n---\n{json_string}\n---")
        return {} # Return empty dict on failure


def transform_finding(finding_data: dict, agent_output: dict, index: int, scan_id: int = 1) -> dict | None:
    """Transforms a CodeQL finding and agent analysis into the frontend format."""
    logger.info(f"Transforming finding {index} (Rule: {finding_data.get('ruleId', 'N/A')})")

    if 'error' in agent_output:
        logger.error(f"Agent returned an error for finding {index}: {agent_output['error']}")
        return None # Skip findings where the agent failed

    agent_json_str = agent_output.get('analysis_json', '{}')
    agent_analysis_parsed = parse_agent_json(agent_json_str)

    if not agent_analysis_parsed:
         logger.warning(f"Skipping finding {index} due to JSON parsing error from agent.")
         return None # Skip if JSON parsing failed

    # Extract location safely
    location = finding_data.get("locations", [{}])[0].get("physicalLocation", {})
    artifact_location = location.get("artifactLocation", {})
    region = location.get("region", {})
    file_path = artifact_location.get('uri', 'Unknown File')
    start_line = region.get('startLine', 0)

    # Map fields
    frontend_finding = {
        "id": index,
        "scan_id": scan_id, # Use a placeholder or pass if needed
        "rule_id": finding_data.get('ruleId', 'Unknown Rule'),
        "message": finding_data.get('message', {}).get('text', 'No message'),
        "file_path": file_path,
        "start_line": start_line,
        # Get LLM fields directly from the parsed agent JSON
        "llm_verification": agent_analysis_parsed.get('verification', 'N/A'),
        "llm_exploitability": agent_analysis_parsed.get('exploitability', 'N/A'),
        "llm_priority": agent_analysis_parsed.get('priority', 'N/A'),
        "llm_remediation": None, # Add if agent provides this
        "code_context": agent_output.get('code_context', ''),
        # Nested analysis object
        "analysis": {
            "description": agent_analysis_parsed.get('description', 'N/A'),
            "dataFlow": agent_analysis_parsed.get('dataFlow', 'N/A'),
            "impact": agent_analysis_parsed.get('impact', 'N/A'),
            "recommendations": agent_analysis_parsed.get('recommendations', []),
            "vulnerableCode": agent_analysis_parsed.get('vulnerableCode', ''),
        },
        "raw_data": {
            'original_finding': finding_data,
            'agent_analysis': agent_output # Store the full agent result
        }
    }
    logger.info(f"Successfully transformed finding {index}")
    return frontend_finding


def main(sarif_path: str, repo_path: str, output_path: str):
    """Loads SARIF, runs agent, transforms, and saves results incrementally."""
    logger.info(f"Loading SARIF file from: {sarif_path}")
    try:
        with open(sarif_path, 'r') as f:
            sarif_data = json.load(f)
    except FileNotFoundError:
        logger.error(f"Error: SARIF file not found at {sarif_path}")
        sys.exit(1)
    except json.JSONDecodeError:
        logger.error(f"Error: Could not parse SARIF file {sarif_path}. Is it valid JSON?")
        sys.exit(1)

    # Basic validation of SARIF structure
    if not sarif_data.get('runs') or not isinstance(sarif_data['runs'], list) or len(sarif_data['runs']) == 0:
         logger.error("Error: SARIF file does not contain any 'runs'. Cannot process.")
         sys.exit(1)

    findings = sarif_data['runs'][0].get('results', [])
    if not findings:
        logger.warning("SARIF file contains a run, but no findings ('results'). Output will be empty.")
        # Create an empty JSON array if no findings
        try:
            with open(output_path, 'w') as f:
                f.write("[]")
            logger.info(f"Saved empty findings array to: {output_path}")
            return # Exit early
        except IOError as e:
            logger.error(f"Error writing empty output file {output_path}: {e}")
            sys.exit(1)

    logger.info(f"Found {len(findings)} findings in the SARIF file.")
    logger.info(f"Initializing CodeAnalysisAgent for repository: {repo_path}")
    agent = CodeAnalysisAgent(repo_path=repo_path)

    processed_count = 0
    try:
        with open(output_path, 'w') as outfile:
            outfile.write("[\n") # Start the JSON array
            first_item = True

            for i, finding in enumerate(findings):
                logger.info(f"--- Processing Finding {i+1}/{len(findings)} ---")
                agent_result = agent.analyze(finding)
                transformed = transform_finding(finding, agent_result, index=i+1)

                if transformed:
                    processed_count += 1
                    if not first_item:
                        outfile.write(",\n") # Add comma before the next item
                    json.dump(transformed, outfile, indent=4) # Write the transformed finding
                    first_item = False
                    logger.info(f"Saved finding {i+1} to {output_path}")
                else:
                    logger.warning(f"Skipped processing finding {i+1} due to agent error or parsing issue.")

            outfile.write("\n]\n") # Close the JSON array

        logger.info(f"Successfully processed and saved {processed_count} out of {len(findings)} findings.")
        logger.info(f"Final results saved to: {output_path}")
        logger.info("Processing complete.")

    except IOError as e:
         logger.error(f"Error writing to output file {output_path} during processing: {e}")
         sys.exit(1)
    except Exception as e:
        # Catch other potential errors during the loop (e.g., agent errors not caught internally)
        logger.error(f"An unexpected error occurred during processing: {e}", exc_info=True)
        # Attempt to close the JSON array gracefully, even if incomplete
        try:
            with open(output_path, 'a') as outfile: # Open in append mode to add closing bracket
                outfile.write("\n]\n")
            logger.info(f"Attempted to close JSON array in {output_path} after error.")
        except IOError:
            logger.error(f"Could not write closing bracket to {output_path} after error.")
        sys.exit(1)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Process a CodeQL SARIF file with CodeAnalysisAgent and transform findings for frontend use.")
    parser.add_argument("--sarif-path", required=True, help="Path to the input CodeQL SARIF file.")
    parser.add_argument("--repo-path", required=True, help="Path to the root of the scanned repository (needed for code context).")
    parser.add_argument("--output-path", required=True, help="Path to save the transformed JSON output file.")
    args = parser.parse_args()

    # Validate paths
    if not os.path.exists(args.sarif_path):
         print(f"Error: SARIF input file not found: {args.sarif_path}")
         sys.exit(1)
    if not os.path.isdir(args.repo_path):
         print(f"Error: Repository path not found or not a directory: {args.repo_path}")
         sys.exit(1)

    main(args.sarif_path, args.repo_path, args.output_path)

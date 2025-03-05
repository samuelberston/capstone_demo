import os
import json
import logging
import requests
from typing import List, Dict, Any, Optional

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class LLMReasoningEngine:
    """
    Provides LLM-based reasoning for security findings to enhance analysis with:
    - Vulnerability verification (reducing false positives)
    - Exploitability assessment
    - Remediation suggestions
    - Priority scoring based on context
    """
    
    def __init__(self, api_key: str, model: str = "gpt-4", api_base: Optional[str] = None):
        """
        Initialize the LLM reasoning engine.
        
        Args:
            api_key: API key for the LLM service
            model: Model to use (default: gpt-4)
            api_base: Optional custom API base URL
        """
        self.api_key = api_key
        self.model = model
        self.api_base = api_base or "https://api.openai.com/v1"
        
    def analyze_codeql_finding(self, finding: Dict[Any, Any], repo_path: str) -> Dict[Any, Any]:
        """
        Analyze a CodeQL finding with LLM reasoning.
        
        Args:
            finding: The CodeQL finding to analyze
            repo_path: Path to the repository for context
            
        Returns:
            Enhanced finding with LLM reasoning
        """
        # Extract relevant information from the finding
        rule_id = finding.get('ruleId', '')
        message = finding.get('message', {}).get('text', '')
        
        # Get source code context
        code_context = self._extract_code_context(finding, repo_path)
        if not code_context:
            logger.warning(f"Could not extract code context for finding: {rule_id}")
            finding['llm_analysis'] = {
                "error": "Could not extract code context for analysis"
            }
            return finding
            
        # Prepare prompt for LLM
        prompt = self._prepare_codeql_prompt(rule_id, message, code_context)
        
        # Get LLM analysis
        llm_response = self._query_llm(prompt)
        
        # Add LLM analysis to the finding
        finding['llm_analysis'] = {
            "verification": self._extract_verification(llm_response),
            "exploitability": self._extract_exploitability(llm_response),
            "remediation": self._extract_remediation(llm_response),
            "priority": self._extract_priority(llm_response),
            "full_analysis": llm_response
        }
        
        return finding
        
    def analyze_dependency_finding(self, finding: Dict[Any, Any], repo_path: str) -> Dict[Any, Any]:
        """
        Analyze a dependency vulnerability finding with LLM reasoning.
        
        Args:
            finding: The dependency finding to analyze
            repo_path: Path to the repository for context
            
        Returns:
            Enhanced finding with LLM reasoning
        """
        # Extract relevant information
        vuln_id = finding.get('vulnerability_id', '')
        description = finding.get('description', '')
        severity = finding.get('severity', '')
        
        # Get dependency usage context if possible
        usage_context = self._extract_dependency_usage(finding, repo_path)
        
        # Prepare prompt for LLM
        prompt = self._prepare_dependency_prompt(vuln_id, description, severity, usage_context)
        
        # Get LLM analysis
        llm_response = self._query_llm(prompt)
        
        # Add LLM analysis to the finding
        finding['llm_analysis'] = {
            "exploitability": self._extract_exploitability(llm_response),
            "remediation": self._extract_remediation(llm_response),
            "priority": self._extract_priority(llm_response),
            "full_analysis": llm_response
        }
        
        return finding
    
    def _extract_code_context(self, finding: Dict[Any, Any], repo_path: str) -> str:
        """Extract relevant code context for a finding."""
        try:
            # Get file path and line information
            locations = finding.get('locations', [])
            if not locations:
                return ""
                
            location = locations[0]
            physical_location = location.get('physicalLocation', {})
            artifact_location = physical_location.get('artifactLocation', {})
            file_path = artifact_location.get('uri', '')
            
            region = physical_location.get('region', {})
            start_line = region.get('startLine', 0)
            
            # Calculate line range (context before and after)
            context_lines = 10
            start_context = max(1, start_line - context_lines)
            end_context = start_line + context_lines
            
            # Read the file
            full_path = os.path.join(repo_path, file_path)
            if not os.path.exists(full_path):
                return ""
                
            with open(full_path, 'r', encoding='utf-8', errors='replace') as f:
                lines = f.readlines()
                
            # Extract the relevant lines
            context_lines = lines[start_context-1:end_context]
            
            # Format the context with line numbers
            formatted_context = ""
            for i, line in enumerate(context_lines, start=start_context):
                marker = "→ " if i == start_line else "  "
                formatted_context += f"{marker}{i}: {line}"
                
            return formatted_context
            
        except Exception as e:
            logger.error(f"Error extracting code context: {str(e)}")
            return ""
    
    def _extract_dependency_usage(self, finding: Dict[Any, Any], repo_path: str) -> str:
        """Extract context about how a dependency is used in the project."""
        try:
            dependency_name = finding.get('dependency_name', '')
            if not dependency_name:
                return ""
                
            # Look for import statements or dependency declarations
            usage_examples = []
            
            # Search for imports in Python files
            for root, _, files in os.walk(repo_path):
                for file in files:
                    if file.endswith('.py'):
                        file_path = os.path.join(root, file)
                        try:
                            with open(file_path, 'r', encoding='utf-8', errors='replace') as f:
                                content = f.read()
                                if dependency_name.lower() in content.lower():
                                    usage_examples.append(f"Used in: {os.path.relpath(file_path, repo_path)}")
                        except:
                            pass
            
            # Check package.json for JS dependencies
            package_json_path = os.path.join(repo_path, 'package.json')
            if os.path.exists(package_json_path):
                try:
                    with open(package_json_path, 'r') as f:
                        package_data = json.load(f)
                        deps = {**package_data.get('dependencies', {}), **package_data.get('devDependencies', {})}
                        if dependency_name in deps:
                            usage_examples.append(f"Declared in package.json with version: {deps[dependency_name]}")
                except:
                    pass
            
            # Check requirements.txt for Python dependencies
            req_txt_path = os.path.join(repo_path, 'requirements.txt')
            if os.path.exists(req_txt_path):
                try:
                    with open(req_txt_path, 'r') as f:
                        for line in f:
                            if dependency_name.lower() in line.lower():
                                usage_examples.append(f"Declared in requirements.txt: {line.strip()}")
                except:
                    pass
            
            return "\n".join(usage_examples) if usage_examples else "No direct usage found in the codebase."
            
        except Exception as e:
            logger.error(f"Error extracting dependency usage: {str(e)}")
            return ""
    
    def _prepare_codeql_prompt(self, rule_id: str, message: str, code_context: str) -> str:
        """Prepare a prompt for CodeQL finding analysis."""
        return f"""You are a security expert analyzing a potential vulnerability found by CodeQL.

FINDING DETAILS:
Rule ID: {rule_id}
Message: {message}

CODE CONTEXT (→ marks the flagged line):
{code_context}

Please analyze this vulnerability and provide:
1. VERIFICATION: Is this likely a true positive or false positive? Explain why.
2. EXPLOITABILITY: How exploitable is this vulnerability? Consider attack vectors and complexity.
3. REMEDIATION: Provide specific code changes to fix this vulnerability.
4. PRIORITY: Assign a priority (Critical, High, Medium, Low) based on impact and exploitability in this specific context.

Format your response with these exact headings."""
    
    def _prepare_dependency_prompt(self, vuln_id: str, description: str, severity: str, usage_context: str) -> str:
        """Prepare a prompt for dependency vulnerability analysis."""
        return f"""You are a security expert analyzing a vulnerable dependency found in a project.

VULNERABILITY DETAILS:
ID: {vuln_id}
Description: {description}
Reported Severity: {severity}

DEPENDENCY USAGE CONTEXT:
{usage_context}

Please analyze this vulnerability and provide:
1. EXPLOITABILITY: How exploitable is this vulnerability in the context of this project? Consider how the dependency is used.
2. REMEDIATION: Provide specific recommendations to fix this vulnerability (update version, alternative library, etc.)
3. PRIORITY: Assign a priority (Critical, High, Medium, Low) based on impact and exploitability in this specific context.

Format your response with these exact headings."""
    
    def _query_llm(self, prompt: str) -> str:
        """Query the LLM with the given prompt."""
        try:
            headers = {
                "Content-Type": "application/json",
                "Authorization": f"Bearer {self.api_key}"
            }
            
            payload = {
                "model": self.model,
                "messages": [{"role": "user", "content": prompt}],
                "temperature": 0.1,  # Low temperature for more deterministic responses
                "max_tokens": 1000
            }
            
            response = requests.post(
                f"{self.api_base}/chat/completions",
                headers=headers,
                json=payload,
                timeout=30
            )
            
            if response.status_code != 200:
                logger.error(f"LLM API error: {response.status_code} - {response.text}")
                return "Error: Could not get LLM analysis"
                
            result = response.json()
            return result['choices'][0]['message']['content']
            
        except Exception as e:
            logger.error(f"Error querying LLM: {str(e)}")
            return f"Error: {str(e)}"
    
    def _extract_verification(self, llm_response: str) -> str:
        """Extract verification assessment from LLM response."""
        try:
            if "VERIFICATION:" in llm_response:
                verification_section = llm_response.split("VERIFICATION:")[1].split("EXPLOITABILITY:")[0]
                return verification_section.strip()
            return "Not provided"
        except:
            return "Not provided"
    
    def _extract_exploitability(self, llm_response: str) -> str:
        """Extract exploitability assessment from LLM response."""
        try:
            if "EXPLOITABILITY:" in llm_response:
                if "REMEDIATION:" in llm_response:
                    exploitability_section = llm_response.split("EXPLOITABILITY:")[1].split("REMEDIATION:")[0]
                else:
                    exploitability_section = llm_response.split("EXPLOITABILITY:")[1].split("PRIORITY:")[0]
                return exploitability_section.strip()
            return "Not provided"
        except:
            return "Not provided"
    
    def _extract_remediation(self, llm_response: str) -> str:
        """Extract remediation suggestions from LLM response."""
        try:
            if "REMEDIATION:" in llm_response:
                remediation_section = llm_response.split("REMEDIATION:")[1].split("PRIORITY:")[0]
                return remediation_section.strip()
            return "Not provided"
        except:
            return "Not provided"
    
    def _extract_priority(self, llm_response: str) -> str:
        """Extract priority assessment from LLM response."""
        try:
            if "PRIORITY:" in llm_response:
                priority_section = llm_response.split("PRIORITY:")[1]
                return priority_section.strip()
            return "Not provided"
        except:
            return "Not provided" 
from typing import Annotated, Dict, Any, List
from typing_extensions import TypedDict
from langchain_openai import ChatOpenAI
from langchain_core.tools import tool
from langgraph.graph import StateGraph, START, END
from langgraph.graph.message import add_messages
from langgraph.prebuilt import ToolNode
import os
import logging
import re
from .usage_analyzer import DependencyUsageAnalyzer, UsageMatch

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Define the state schema
class State(TypedDict):
    messages: Annotated[list, add_messages]
    context: Dict[str, Any]  # Store dependency context and analysis results
    dependency: Dict[str, Any]  # Store the current dependency being analyzed
    dependency_name: str
    vulnerability_info: Dict
    usage_info: Dict
    analysis: Dict

class DependencyAnalysisAgent:
    def __init__(self, repo_path: str = None):
        logger.info(f"Initializing DependencyAnalysisAgent with repo path: {repo_path}")
        self.repo_path = repo_path
        self.usage_analyzer = DependencyUsageAnalyzer(repo_path) if repo_path else None
        self.graph_builder = StateGraph(State)
        
        logger.info("Initializing LLM")
        self.llm = ChatOpenAI(model="gpt-4")
        
        logger.info("Setting up graph structure")
        self._setup_graph()

    def _setup_graph(self):
        """Configure the state graph with nodes and edges"""
        logger.info("Configuring state graph nodes and edges")
        
        # Add nodes
        self.graph_builder.add_node("analyze_dependency", self._analyze_dependency_node)
        self.graph_builder.add_node("extract_context", self._extract_context_node)
        
        # Simplify the graph flow
        logger.info("Configuring graph edges")
        self.graph_builder.add_edge(START, "extract_context")
        self.graph_builder.add_edge("extract_context", "analyze_dependency")
        self.graph_builder.add_edge("analyze_dependency", END)  # Go straight to END after analysis

    def _analyze_dependency_node(self, state: State) -> Dict:
        """Node for analyzing dependencies"""
        logger.info("Running dependency analysis node")
        try:
            messages = state.get("messages", [])
            context = state.get("context", {})
            dependency = state.get("dependency", {})
            
            # Get the version from the dependency data
            dependency_version = dependency.get('version', '0.1.3')
            logger.info(f"Analyzing dependency: {dependency.get('name')} @ {dependency_version}")
            
            # Get file contents where dependency is used
            usage = context.get('usage', {})
            file_contents = usage.get('file_contents', {})
            
            logger.info(f"Usage summary: {len(file_contents)} relevant files found")
            
            # Focus on the file that imports the dependency
            relevant_file = next(
                (import_info.file for import_info in usage.get('import_statements', [])
                 if import_info.file in file_contents),
                None
            )
            
            if relevant_file:
                file_content = file_contents.get(relevant_file, '')
                logger.info(f"Found relevant file content from {relevant_file}")
            else:
                file_content = "File content not found"
                logger.warning("Could not find content of file with import")
            
            # First get detailed analysis
            analysis_prompt = {
                "role": "system",
                "content": """You are a security expert analyzing a dependency for vulnerabilities.
Analyze the dependency usage, known vulnerabilities, and provide specific recommendations."""
            }
            
            # Format vulnerability information dynamically
            vuln_details = []
            for vuln in context.get('vulnerabilities', []):
                vuln_details.append(f"- {vuln.get('name', 'Unknown CVE')}: {vuln.get('description', 'No description')}")
                if vuln.get('cvssScore'):
                    vuln_details.append(f"- CVSS Score: {vuln['cvssScore']} ({vuln.get('severity', 'Unknown')})")
                if vuln.get('affectedVersions'):
                    vuln_details.append(f"- Affects versions: {vuln['affectedVersions']}")
            
            vuln_text = "\n".join(vuln_details) if vuln_details else "No known vulnerabilities"
            
            analysis_request = {
                "role": "user",
                "content": f"""Analyze this dependency for security implications:

Dependency: {dependency.get('name')}
Version: {dependency_version}

Implementation in {relevant_file}:
```typescript
{file_content}
```

Known vulnerabilities:
{vuln_text}

Please provide:
1. Analysis of how the dependency is used in the codebase
2. Whether the vulnerability appears exploitable based on usage
3. Specific recommendations for remediation"""
            }
            
            logger.info("Requesting initial analysis from LLM")
            analysis = self.llm.invoke([analysis_prompt, analysis_request])
            
            # Then format as JSON with a specific structure
            json_prompt = {
                "role": "system",
                "content": """You are a security data formatter. Format the dependency analysis as JSON using ONLY the provided vulnerability data - do not substitute or omit any vulnerability information.

For each vulnerability in the input data, you MUST include:
- The exact CVE ID
- The exact CVSS score
- The exact severity level
- All CWE IDs
- The full vulnerability description

Example structure:
{
    "dependency": {
        "name": "package-name",
        "version": "x.y.z",
        "vulnerableVersions": "The exact version range from CVE data"
    },
    "usage": {
        "implementation": "How the dependency is used",
        "relevantFile": "File path",
        "configurationDetails": "Configuration details"
    },
    "vulnerabilities": {
        "cves": ["Exact CVE IDs from input"],
        "severity": "Highest severity from input",
        "cvssScore": "Highest CVSS score from input",
        "description": "Description from most severe CVE",
        "exploitable": "Whether exploitable based on usage",
        "cwes": ["All CWE IDs from input"]
    },
    "recommendations": []
}"""
            }
            
            json_request = {
                "role": "user",
                "content": f"""Format this security data as JSON, using EXACTLY these vulnerability details:

Vulnerability Data:
CVE IDs: {[v.get('name') for v in context.get('vulnerabilities', [])]}
Severities: {[v.get('severity') for v in context.get('vulnerabilities', [])]}
CVSS Scores: {[v.get('cvssv3', {}).get('baseScore') for v in context.get('vulnerabilities', [])]}
CWEs: {[cwe for v in context.get('vulnerabilities', []) for cwe in v.get('cwes', [])]}
Description: {next((v.get('description') for v in context.get('vulnerabilities', []) if v.get('severity') == 'CRITICAL'), 'No description available')}
Affected Versions: {next((v.get('vulnerableSoftware', [{}])[0].get('software', {}).get('versionEndIncluding') for v in context.get('vulnerabilities', [])), 'Unknown')}

Usage Analysis:
Dependency: {dependency.get('name')}@{dependency_version}
File: {relevant_file}
Analysis: {analysis.content}"""
            }
            
            logger.info("Requesting JSON formatting of analysis")
            json_response = self.llm.invoke([json_prompt, json_request])
            
            # Return formatted results
            analysis_result = {
                "messages": [analysis],
                "analysis": {
                    "content": analysis.content,
                    "json_format": json_response.content
                }
            }
            
            return analysis_result
            
        except Exception as e:
            logger.error(f"Error in dependency analysis: {str(e)}", exc_info=True)
            return {"error": str(e)}

    def _extract_context_node(self, state: State) -> Dict:
        """Node for extracting dependency context"""
        logger.info("Extracting dependency context")
        try:
            dependency = state.get("dependency", {})
            # Log only essential dependency information
            logger.info(f"Processing dependency: {dependency.get('name')}@{dependency.get('version')}")
            
            # Extract relevant context about the dependency
            usage = self._find_dependency_usage(dependency.get("name"))
            # Log concise usage summary
            logger.info(f"Found usage patterns: {len(usage.get('import_statements', []))} imports, "
                       f"{len(usage.get('configuration', []))} configurations, "
                       f"{len(usage.get('direct_usage', []))} direct usages")
            
            context = {
                "usage": usage,
            }
            
            return {"context": context}
            
        except Exception as e:
            logger.error(f"Error extracting context: {str(e)}", exc_info=True)
            return {"error": str(e)}

    def _extract_vulnerability_info(self, context: Dict) -> Dict:
        """Extract vulnerability information from dependency-check findings"""
        vuln_info = {
            'vulnerabilities': context.get('vulnerabilities', []),
            'cves': [],
            'severities': set(),
            'cwes': []
        }
        
        for vuln in vuln_info['vulnerabilities']:
            if vuln.get('name', '').startswith('CVE-'):
                vuln_info['cves'].append(vuln['name'])
            vuln_info['severities'].add(vuln.get('severity', '').upper())
            if vuln.get('cwes'):
                vuln_info['cwes'].extend(vuln.get('cwes', []))
        
        return vuln_info

    def _format_vulnerability_details(self, vuln_info: Dict) -> str:
        """Format vulnerability details for analysis prompt"""
        details = []
        for vuln in vuln_info.get('vulnerabilities', []):
            details.append(f"""
- ID: {vuln.get('name')}
- Severity: {vuln.get('severity', 'Unknown')}
- Description: {vuln.get('description', 'No description available')}
- CWEs: {', '.join(vuln.get('cwes', []))}
""")
        return '\n'.join(details)

    def _format_cvss_scores(self, vuln_info: Dict) -> str:
        """Format CVSS scores for analysis prompt"""
        scores = []
        for vuln in vuln_info.get('vulnerabilities', []):
            if vuln.get('cvssv3'):
                scores.append(f"""
CVSS v3 Score: {vuln['cvssv3'].get('baseScore')} ({vuln['cvssv3'].get('baseSeverity')})
- Attack Vector: {vuln['cvssv3'].get('attackVector')}
- Attack Complexity: {vuln['cvssv3'].get('attackComplexity')}
- Privileges Required: {vuln['cvssv3'].get('privilegesRequired')}
- User Interaction: {vuln['cvssv3'].get('userInteraction')}
""")
        return '\n'.join(scores) if scores else "No CVSS scores available"

    def _find_dependency_usage(self, name: str) -> Dict:
        """Find how the dependency is used in the codebase."""
        if not self.usage_analyzer:
            logger.warning("No repository path provided, skipping usage analysis")
            return {"error": "No repository path provided"}
            
        return self.usage_analyzer.analyze_usage(name)

    @tool
    def analyze_dependency_usage(self, name: str, version: str) -> str:
        """
        Analyze how a dependency is used in the codebase.
        Args:
            name: Name of the dependency
            version: Version of the dependency
        Returns:
            String containing analysis of dependency usage
        """
        usage_info = self._find_dependency_usage(name)
        if "error" in usage_info:
            return f"Error analyzing dependency usage: {usage_info['error']}"
            
        imports = len(usage_info.get('import_statements', []))
        configs = len(usage_info.get('configuration', []))
        files = len(usage_info.get('file_contents', {}))
        
        return f"Found {imports} imports and {configs} configurations across {files} files"

    def analyze(self, dependency: Dict) -> Dict:
        """
        Main entry point for dependency analysis
        Args:
            dependency: Dictionary containing dependency information
        Returns:
            Dictionary containing analysis results
        """
        logger.info(f"Starting analysis for dependency: {dependency.get('name')}")
        try:
            # Compile the graph
            graph = self.graph_builder.compile()
            
            # Initial state
            initial_state = {
                "messages": [],
                "context": {},
                "dependency": dependency,
                "dependency_name": dependency.get('name'),
                "vulnerability_info": self._extract_vulnerability_info(dependency.get("context", {})),
                "usage_info": self._find_dependency_usage(dependency.get("name")),
                "analysis": {}
            }
            
            # Run the graph
            result = graph.invoke(initial_state)
            logger.info("Dependency analysis completed successfully")
            return result
            
        except Exception as e:
            logger.error(f"Error in dependency analysis: {str(e)}", exc_info=True)
            return {"error": str(e)}

    def _get_code_context(self, file_path: str, line_number: int, context_lines: int = 5) -> str:
        """Get lines of code before and after a specific line number.
        
        Args:
            file_path: Path to the source file
            line_number: The line number to get context around
            context_lines: Number of lines before and after to include
            
        Returns:
            String containing the code context with line numbers
        """
        try:
            with open(os.path.join(self.repo_path, file_path), 'r', encoding='utf-8') as f:
                lines = f.readlines()
                
            start = max(0, line_number - context_lines - 1)
            end = min(len(lines), line_number + context_lines)
            
            context = []
            for i in range(start, end):
                prefix = '> ' if i == line_number - 1 else '  '
                context.append(f"{prefix}{i+1}: {lines[i].rstrip()}")
                
            return '\n'.join(context)
            
        except Exception as e:
            logger.error(f"Error getting code context from {file_path}: {str(e)}")
            return f"Error: Could not read file {file_path}"
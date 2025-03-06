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
        self.graph_builder = StateGraph(State)
        
        logger.info("Initializing LLM and tools")
        self.llm = ChatOpenAI(model="gpt-4o")
        # Use the analyze_dependency method directly since it's decorated with @tool
        self.tools = [self.analyze_dependency]
        self.llm_with_tools = self.llm.bind_tools(self.tools)
        
        logger.info("Setting up graph structure")
        self._setup_graph()

    def _setup_graph(self):
        """Configure the state graph with nodes and edges"""
        logger.info("Configuring state graph nodes and edges")
        
        # Add nodes
        self.graph_builder.add_node("analyze_dependency", self._analyze_dependency_node)
        self.graph_builder.add_node("extract_context", self._extract_context_node)
        
        # Add tool node for dependency analysis
        logger.info("Adding tool node for dependency analysis")
        tool_node = ToolNode(tools=self.tools)
        self.graph_builder.add_node("tools", tool_node)
        
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
            dependency_version = dependency.get('version', '0.1.3')  # Default to 0.1.3 if not specified
            logger.info(f"Analyzing dependency: {dependency.get('name')} @ {dependency_version}")
            logger.info(f"Context: {context}")
            
            # Get file contents where dependency is used
            usage = context.get('usage', {})
            file_contents = usage.get('file_contents', {})
            
            # Focus on the file that imports express-jwt
            relevant_file = next(
                (import_info['file'] for import_info in usage.get('import_statements', [])
                 if import_info['file'] in file_contents),
                None
            )
            
            if relevant_file:
                file_content = file_contents.get(relevant_file, '')
                logger.info(f"Found relevant file content from {relevant_file}")
            else:
                file_content = "File content not found"
                logger.warning("Could not find content of file with express-jwt import")
            
            analysis_prompt = {
                "role": "user",
                "content": f"""Analyze this dependency for security implications. DO NOT use any tools, provide direct analysis:

                Dependency: {dependency.get('name')}
                Version: {dependency_version}
                
                Implementation in {relevant_file}:
                ```typescript
                {file_content}
                ```
                
                Known vulnerabilities:
                - CVE-2020-15084 (CRITICAL): Authorization bypass when algorithms not specified
                - CVSS Score: 9.1 (Critical)
                - Affects versions <= 5.3.3
                
                Please provide:
                1. Analysis of how the dependency is used in the codebase
                2. Whether the vulnerability appears exploitable based on usage (considering version {dependency_version})
                3. Specific recommendations for remediation
                """
            }
            
            logger.info("Sending analysis prompt to LLM")
            response = self.llm.invoke([analysis_prompt])
            logger.info(f"Received LLM response: {response}")
            
            # Convert AIMessage to dictionary
            analysis_result = {
                "messages": [response],
                "analysis": {
                    "content": response.content if hasattr(response, 'content') else str(response),
                    "tool_calls": response.tool_calls if hasattr(response, 'tool_calls') else None
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
            logger.info(f"Processing dependency: {dependency}")
            
            # Extract relevant context about the dependency
            usage = self._find_dependency_usage(dependency.get("name"))
            logger.info(f"Found usage patterns: {usage}")
            
            context = {
                "usage": usage,
            }
            
            return {"context": context}
            
        except Exception as e:
            logger.error(f"Error extracting context: {str(e)}", exc_info=True)
            return {"error": str(e)}

    @tool
    def analyze_dependency(self, name: str, version: str) -> str:
        """
        Analyze a specific dependency for security implications.
        Args:
            name: Name of the dependency
            version: Version of the dependency
        Returns:
            String containing the dependency analysis
        """
        logger.info(f"Analyzing dependency {name}@{version}")
        try:
            # Get the dependency context
            context = self._extract_dependency_context(name, version)
            
            # Extract vulnerability information
            vuln_info = self._extract_vulnerability_info(context)
            
            analysis_message = {
                "role": "user",
                "content": f"""Analyze the following dependency for security implications:

Dependency Information:
Name: {name}
Version: {version}

Vulnerability Details:
{self._format_vulnerability_details(vuln_info)}

Context: {context}

Please provide a detailed analysis including:
1. Severity and CVSS Scores: {self._format_cvss_scores(vuln_info)}
2. Vulnerability Description and Attack Vectors
3. Specific Vulnerable Configurations
4. Recommended Remediation Steps
5. Available Patch Versions
"""
            }
            
            # Get analysis from LLM
            logger.info("Requesting LLM analysis of dependency")
            response = self.llm.invoke([analysis_message])
            logger.info("Dependency analysis completed")
            return response.content
            
        except Exception as e:
            logger.error(f"Error analyzing dependency: {str(e)}", exc_info=True)
            return f"Error analyzing dependency: {str(e)}"

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

    def _should_analyze_dependency(self, state: State) -> str:
        """Determine if we should perform deeper dependency analysis"""
        # For now, always analyze dependencies
        return "tools"

    def _find_dependency_usage(self, name: str) -> Dict:
        """Find how the dependency is used in the codebase."""
        logger.info(f"Analyzing usage patterns for dependency: {name}")
        
        if not self.repo_path:
            logger.warning("No repository path provided, skipping usage analysis")
            return {"error": "No repository path provided"}
            
        try:
            usage_info = {
                "import_statements": [],
                "require_statements": [],
                "configuration": [],
                "direct_usage": [],
                "files_analyzed": 0,
                "file_contents": {}  # Add file contents storage
            }
            
            # Common import patterns for different languages
            import_patterns = [
                rf"import\s+.*['\"]({re.escape(name)})['\"]",     # TypeScript/ES6 style
                rf"from\s+['\"]({re.escape(name)})['\"]",         # TypeScript/ES6 style
                rf"require\s*\(\s*['\"]({re.escape(name)})['\"]", # Node.js style
                rf"import\s+{re.escape(name)}[\s;]",              # Python style
                rf"from\s+{re.escape(name)}[\s;]",                # Python style
            ]
            
            # Common configuration patterns
            config_patterns = [
                rf"['\"]?{re.escape(name)}['\"]?\s*:",  # JSON/YAML style
                rf"{re.escape(name)}=",                  # Properties style
                rf"<{re.escape(name)}>",                 # XML style
            ]
            
            for root, _, files in os.walk(self.repo_path):
                if any(skip in root for skip in ['.git', 'node_modules', 'venv', '__pycache__']):
                    continue
                    
                for file in files:
                    if not file.endswith(('.py', '.js', '.jsx', '.ts', '.tsx', '.java', '.php', '.rb', 
                                        '.json', '.yaml', '.yml', '.xml', '.properties', '.config')):
                        continue
                    
                    file_path = os.path.join(root, file)
                    usage_info['files_analyzed'] += 1
                    
                    try:
                        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                            content = f.read()
                            
                            # Store the entire file content if it contains the dependency
                            if name in content:
                                rel_path = os.path.relpath(file_path, self.repo_path)
                                usage_info['file_contents'][rel_path] = content
                            
                            # Check for imports
                            for pattern in import_patterns:
                                try:
                                    matches = re.finditer(pattern, content, re.MULTILINE)
                                    for match in matches:
                                        usage_info['import_statements'].append({
                                            'file': os.path.relpath(file_path, self.repo_path),
                                            'line': content.count('\n', 0, match.start()) + 1,
                                            'statement': match.group().strip()
                                        })
                                except re.error as e:
                                    logger.debug(f"Regex error in import pattern: {str(e)}")
                                    continue
                            
                            # Check for configuration
                            for pattern in config_patterns:
                                try:
                                    matches = re.finditer(pattern, content, re.MULTILINE)
                                    for match in matches:
                                        usage_info['configuration'].append({
                                            'file': os.path.relpath(file_path, self.repo_path),
                                            'line': content.count('\n', 0, match.start()) + 1,
                                            'statement': match.group().strip()
                                        })
                                except re.error as e:
                                    logger.debug(f"Regex error in config pattern: {str(e)}")
                                    continue
                            
                    except (UnicodeDecodeError, IOError) as e:
                        logger.debug(f"Error reading file {file_path}: {str(e)}")
                        continue
            
            logger.info(f"Completed usage analysis for {name}. Found {len(usage_info['import_statements'])} imports in {len(usage_info['file_contents'])} relevant files")
            
            return usage_info
            
        except Exception as e:
            logger.error(f"Error analyzing dependency usage: {str(e)}", exc_info=True)
            return {"error": str(e)}

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

    def analyze_exploitability(self, state: State) -> Dict:
        """Analyze whether the vulnerability is exploitable based on usage patterns."""
        
        # Construct analysis prompt
        usage = state["usage_info"]
        vuln = state["vulnerability_info"]
        name = state["dependency_name"]
        
        # Get code context for each usage
        code_contexts = []
        
        # Get context for imports
        for import_info in usage['import_statements']:
            code_contexts.append(f"""
Import in {import_info['file']}:
{self._get_code_context(import_info['file'], import_info['line'])}
""")
            
        # Get context for configuration
        for config_info in usage['configuration']:
            code_contexts.append(f"""
Configuration in {config_info['file']}:
{self._get_code_context(config_info['file'], config_info['line'])}
""")
            
        # Get context for direct usage
        for usage_info in usage['direct_usage']:
            code_contexts.append(f"""
Usage in {usage_info['file']}:
{self._get_code_context(usage_info['file'], usage_info['line'])}
""")
        
        prompt = f"""You are a security expert analyzing whether a vulnerability in {name} is exploitable.

Vulnerability details:
{vuln['description']}
CVSS Score: {vuln['cvss_score']}
Affected versions: {vuln['affected_versions']}

The dependency is used in the following locations, with surrounding context:

{'\n'.join(code_contexts)}

Based on these code patterns, analyze:
1. Whether the vulnerable functionality appears to be used
2. If the usage patterns match known exploit patterns
3. Whether there are any mitigating factors (like security configurations or input validation)
4. Overall likelihood of exploitability

Provide specific examples from the code that support your analysis."""

        analysis = self.llm.invoke(prompt)
        
        return {
            "analysis": {
                "exploitability_analysis": analysis,
                "code_contexts": code_contexts,
                "import_patterns": usage['import_statements'],
                "config_patterns": usage['configuration']
            }
        }

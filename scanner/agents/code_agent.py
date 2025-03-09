from typing import Annotated, Dict, Any
from typing_extensions import TypedDict
from langchain_openai import ChatOpenAI
from langchain_core.tools import tool
from langgraph.graph import StateGraph, START, END
from langgraph.graph.message import add_messages
from langgraph.prebuilt import ToolNode
import os
import logging

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Define the state schema
class State(TypedDict):
    messages: Annotated[list, add_messages]
    context: Dict[str, Any]  # Store code context, analysis results, and CodeQL findings
    codeql_finding: Dict[str, Any]  # Store the current CodeQL finding being analyzed
    
class CodeAnalysisAgent:
    def __init__(self, repo_path: str = None):
        logger.info(f"Initializing CodeAnalysisAgent with repo path: {repo_path}")
        self.repo_path = repo_path
        self.graph_builder = StateGraph(State)
        
        logger.info("Initializing LLM and tools")
        self.llm = ChatOpenAI(model="gpt-4o")
        # Use the analyze_code_flow method directly since it's decorated with @tool
        self.tools = [self.analyze_code_flow]
        self.llm_with_tools = self.llm.bind_tools(self.tools)
        
        logger.info("Setting up graph structure")
        self._setup_graph()
        
    def _setup_graph(self):
        """Configure the state graph with nodes and edges"""
        logger.info("Configuring state graph nodes and edges")
        
        # Add nodes
        self.graph_builder.add_node("analyze_code", self._analyze_code_node)
        self.graph_builder.add_node("extract_context", self._extract_context_node)
        
        # Add tool node for code flow analysis
        logger.info("Adding tool node for code flow analysis")
        tool_node = ToolNode(tools=self.tools)
        self.graph_builder.add_node("tools", tool_node)
        
        # Add edges with conditional routing
        logger.info("Configuring graph edges and conditional routing")
        self.graph_builder.add_edge(START, "extract_context")
        self.graph_builder.add_edge("extract_context", "analyze_code")
        
        # Add conditional edge to check if we need code flow analysis
        self.graph_builder.add_conditional_edges(
            "analyze_code",
            self._should_analyze_flow,
            {
                "tools": "tools",
                END: END
            }
        )
        self.graph_builder.add_edge("tools", END)
        
        # Compile the graph
        logger.info("Compiling graph")
        self.graph = self.graph_builder.compile()

    def _extract_context_node(self, state: State) -> Dict:
        """Node for extracting code context"""
        logger.info("Extracting code context")
        try:
            context = state.get("context", {})
            finding = state.get("codeql_finding", {})
            
            # Extract location details
            location = finding.get("locations", [{}])[0].get("physicalLocation", {})
            artifact_location = location.get("artifactLocation", {})
            region = location.get("region", {})
            
            file_path = artifact_location.get("uri", context.get("file_path"))
            start_line = region.get("startLine", context.get("start_line"))
            end_line = region.get("endLine", context.get("end_line"))
            
            logger.info(f"Processing file: {file_path} (lines {start_line}-{end_line})")
            
            # Extract code flows with more detail
            code_flows = finding.get("codeFlows", [])
            flow_context = ""
            if code_flows:
                logger.info(f"Found {len(code_flows)} code flows to analyze")
                flow_context = "\nData Flow Analysis:\n"
                for flow_idx, flow in enumerate(code_flows, 1):
                    flow_context += f"\nFlow Path {flow_idx}:\n"
                    for thread_flow in flow.get("threadFlows", []):
                        for step_idx, loc in enumerate(thread_flow.get("locations", []), 1):
                            loc_info = loc.get("location", {})
                            phys_loc = loc_info.get("physicalLocation", {})
                            region = phys_loc.get("region", {})
                            message = loc_info.get("message", {}).get("text", "")
                            
                            # Get code context for this step
                            step_line = region.get("startLine")
                            if step_line:
                                step_code = self._extract_code_context(
                                    file_path, 
                                    step_line, 
                                    region.get("endLine", step_line)
                                )
                                flow_context += f"\nStep {step_idx}:\n"
                                flow_context += f"Location: Line {step_line}\n"
                                flow_context += f"Operation: {message}\n"
                                flow_context += f"Code:\n{step_code}\n"
            
            if not all([file_path, start_line]):
                logger.error("Missing required context for code analysis")
                return {"messages": ["Missing required context for code analysis"]}
                
            code_context = self._extract_code_context(
                file_path, start_line, end_line or start_line + 5
            )
            
            logger.info("Successfully extracted code context and flow information")
            return {
                "context": {**context, "code_context": code_context, "flow_context": flow_context},
                "messages": [
                    {"role": "system", "content": f"""
CodeQL Finding: {finding.get('message', {}).get('text', '')}
Rule ID: {finding.get('ruleId', 'Unknown')}

Vulnerable Code Location:
{code_context}

Complete Data Flow Analysis:
{flow_context}
"""}
                ]
            }
            
        except Exception as e:
            logger.error(f"Error extracting code context: {str(e)}", exc_info=True)
            return {"messages": [{"role": "system", "content": f"Error: {str(e)}"}]}

    def _analyze_code_node(self, state: State) -> Dict:
        """Node for analyzing code with LLM"""
        logger.info("Starting code analysis with LLM")
        try:
            context = state.get("context", {})
            code_context = context.get("code_context", "")
            flow_context = context.get("flow_context", "")
            finding = state.get("codeql_finding", {})
            
            logger.info(f"Analyzing finding: {finding.get('ruleId', 'Unknown')}")
            
            # First get the detailed analysis
            analysis = self.llm.invoke([
                {"role": "system", "content": """You are a security code analysis assistant. 
Analyze the following code, data flow, and CodeQL finding to explain the security vulnerability and suggest fixes.
Pay special attention to how data flows through the code and where it might be misused."""},
                {"role": "user", "content": f"""
CodeQL Finding: {finding.get('message', {}).get('text', '')}
Rule ID: {finding.get('ruleId', 'Unknown')}

Vulnerable Code:
{code_context}

Data Flow Analysis:
{flow_context}

Please provide a detailed analysis including:
1. Description of the vulnerability
2. Data flow explanation (how the vulnerable data moves through the code)
3. Potential impact
4. Recommended fixes
"""}
            ])

            # Format the analysis as JSON with a more explicit prompt and include the code context
            json_format = self.llm.invoke([
                {"role": "system", "content": """You are a JSON formatter. Convert the security analysis into a JSON object with the following structure:
{
    "description": "Brief description of the vulnerability",
    "dataFlow": "Explanation of how data moves through the code",
    "impact": "Description of potential security impacts",
    "recommendations": ["Array of specific recommendations"],
    "vulnerableCode": "The relevant code snippet showing the vulnerability",
    "location": "File and line number where the vulnerability exists"
}
Ensure the output is valid JSON and contains only these fields."""},
                {"role": "user", "content": f"""Format this security analysis as JSON, including the vulnerable code snippet:

Analysis:
{analysis.content}

Code Context:
{code_context}

File Location: {finding.get('locations', [{}])[0].get('physicalLocation', {}).get('artifactLocation', {}).get('uri', 'Unknown')}
"""}
            ])
            
            if "codeFlows" in finding:
                logger.info("Code flows detected, marking for flow analysis")
                context["needs_flow_analysis"] = True
                
            logger.info("Code analysis completed successfully")
            return {
                "context": {**context, "analysis": analysis.content, "analysis_json": json_format.content},
                "messages": [{"role": "assistant", "content": analysis.content}],
                "codeql_finding": finding
            }
            
        except Exception as e:
            logger.error(f"Error analyzing code: {str(e)}", exc_info=True)
            return {"messages": [{"role": "system", "content": f"Error: {str(e)}"}], "error": str(e)}

    def _extract_code_context(self, file_path: str, start_line: int, end_line: int) -> str:
        """Extract code context from file"""
        try:
            full_path = os.path.join(self.repo_path, file_path) if self.repo_path else file_path
            
            if not os.path.exists(full_path):
                logger.error(f"File not found: {full_path}")
                return f"File not found: {full_path}"
                
            with open(full_path, 'r', encoding='utf-8', errors='replace') as f:
                lines = f.readlines()
                
            # Adjust for 0-based indexing
            start_line = start_line - 1
            end_line = end_line - 1
            
            # Add context by including a few lines before and after
            context_start = max(0, start_line - 3)
            context_end = min(len(lines), end_line + 3)
            
            # Extract the relevant lines
            context_lines = lines[context_start:context_end]
            
            # Format the context with line numbers (convert back to 1-based for display)
            formatted_context = ""
            for i, line in enumerate(context_lines, start=context_start + 1):
                marker = "→ " if start_line + 1 <= i <= end_line + 1 else "  "
                formatted_context += f"{marker}{i}: {line}"
                
            return formatted_context
            
        except Exception as e:
            logger.error(f"Error extracting code context: {str(e)}")
            return f"Error reading file: {str(e)}"

    def analyze(self, codeql_finding: Dict[str, Any]) -> Dict[str, Any]:
        """Main entry point for code analysis"""
        logger.info("Starting analysis of CodeQL finding")
        try:
            # Initialize state with CodeQL finding
            initial_state = {
                "messages": [],
                "context": {},
                "codeql_finding": codeql_finding
            }
            
            # Run the graph
            logger.info("Running analysis graph")
            final_state = self.graph.invoke(initial_state)
            
            logger.info("Analysis completed successfully")
            return {
                "analysis": final_state.get("context", {}).get("analysis", ""),
                "analysis_json": final_state.get("context", {}).get("analysis_json", ""),
                "code_context": final_state.get("context", {}).get("code_context", ""),
                "finding": codeql_finding
            }
            
        except Exception as e:
            logger.error(f"Error in code analysis: {str(e)}", exc_info=True)
            return {"error": str(e)}

    @tool
    def analyze_code_flow(self, file_path: str, start_line: int, end_line: int) -> str:
        """
        Analyze the code flow for a given file and line range.
        Args:
            file_path: Path to the file to analyze
            start_line: Starting line number
            end_line: Ending line number
        Returns:
            String containing the code flow analysis
        """
        logger.info(f"Analyzing code flow for {file_path} (lines {start_line}-{end_line})")
        try:
            # Get the code context first
            code_context = self._extract_code_context(file_path, start_line, end_line)
            
            # Extract any flow steps from the finding
            flow_message = {
                "role": "user",
                "content": f"""Analyze the following code flow and explain how data flows through the code:

Code Context:
{code_context}

Please explain:
1. How data enters this code section
2. How it is processed/transformed
3. Where it exits or is used
4. Any security implications of this flow
"""
            }
            
            # Get analysis from LLM
            logger.info("Requesting LLM analysis of code flow")
            response = self.llm.invoke([flow_message])
            logger.info("Code flow analysis completed")
            return response.content
            
        except Exception as e:
            logger.error(f"Error analyzing code flow: {str(e)}", exc_info=True)
            return f"Error analyzing code flow: {str(e)}"

    def _should_analyze_flow(self, state: State) -> str:
        """Determine if we should analyze code flow"""
        finding = state.get("codeql_finding", {})
        
        # Check if there are code flow steps in the finding
        has_flows = "codeFlows" in finding
        logger.info(f"Checking for code flows: {'found' if has_flows else 'none found'}")
        
        return "tools" if has_flows else END

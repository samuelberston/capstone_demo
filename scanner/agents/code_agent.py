from typing import Annotated, Dict, Any
from typing_extensions import TypedDict
from langchain_openai import ChatOpenAI
from langgraph.graph import StateGraph, START, END
from langgraph.graph.message import add_messages
from langgraph.prebuilt import ToolNode
import os
import logging

logger = logging.getLogger(__name__)

# Define the state schema
class State(TypedDict):
    messages: Annotated[list, add_messages]
    context: Dict[str, Any]  # Store code context, analysis results, and CodeQL findings
    codeql_finding: Dict[str, Any]  # Store the current CodeQL finding being analyzed
    
class CodeAnalysisAgent:
    def __init__(self, repo_path: str = None):
        # Initialize with repository path
        self.repo_path = repo_path
        # Initialize the state graph
        self.graph_builder = StateGraph(State)
        
        # Initialize LLM
        self.llm = ChatOpenAI(model="gpt-4")
        
        # Set up the graph nodes and edges
        self._setup_graph()
        
    def _setup_graph(self):
        """Configure the state graph with nodes and edges"""
        
        # Add nodes
        self.graph_builder.add_node("analyze_code", self._analyze_code_node)
        self.graph_builder.add_node("extract_context", self._extract_context_node)
        
        # Add edges
        self.graph_builder.add_edge(START, "extract_context")
        self.graph_builder.add_edge("extract_context", "analyze_code") 
        self.graph_builder.add_edge("analyze_code", END)
        
        # Compile the graph
        self.graph = self.graph_builder.compile()

    def _extract_context_node(self, state: State) -> Dict:
        """Node for extracting code context"""
        try:
            context = state.get("context", {})
            finding = state.get("codeql_finding", {})
            
            # Extract location from CodeQL finding
            location = finding.get("locations", [{}])[0].get("physicalLocation", {})
            artifact_location = location.get("artifactLocation", {})
            region = location.get("region", {})
            
            file_path = artifact_location.get("uri", context.get("file_path"))
            start_line = region.get("startLine", context.get("start_line"))
            end_line = region.get("endLine", context.get("end_line"))
            
            # Extract code flows for better context
            code_flows = finding.get("codeFlows", [])
            flow_context = ""
            if code_flows:
                flow_context = "\nData flow path:\n"
                for flow in code_flows:
                    for thread_flow in flow.get("threadFlows", []):
                        for loc in thread_flow.get("locations", []):
                            loc_info = loc.get("location", {})
                            message = loc_info.get("message", {}).get("text", "")
                            if message:
                                flow_context += f"- {message}\n"
            
            if not all([file_path, start_line]):
                return {"messages": ["Missing required context for code analysis"]}
                
            code_context = self._extract_code_context(
                file_path, start_line, end_line or start_line + 5
            )
            
            return {
                "context": {**context, "code_context": code_context, "flow_context": flow_context},
                "messages": [
                    {"role": "system", "content": f"""
CodeQL Finding: {finding.get('message', {}).get('text', '')}
Rule ID: {finding.get('ruleId', 'Unknown')}

Affected Code:
{code_context}

{flow_context}
"""}
                ]
            }
            
        except Exception as e:
            logger.error(f"Error extracting code context: {str(e)}")
            return {"messages": [{"role": "system", "content": f"Error: {str(e)}"}]}

    def _analyze_code_node(self, state: State) -> Dict:
        """Node for analyzing code with LLM"""
        try:
            context = state.get("context", {})
            code_context = context.get("code_context", "")
            finding = state.get("codeql_finding", {})
            
            # Enhanced prompt for security analysis
            analysis = self.llm.invoke([
                {"role": "system", "content": "You are a security code analysis assistant. Analyze the following code and CodeQL finding to explain the security vulnerability and suggest fixes."},
                {"role": "user", "content": f"""
CodeQL Finding: {finding.get('message', {}).get('text', '')}
Rule ID: {finding.get('ruleId', 'Unknown')}

Affected Code:
{code_context}

Please analyze the security vulnerability and provide:
1. Description of the vulnerability
2. Potential impact
3. Recommended fixes
"""}
            ])
            
            return {
                "context": {**context, "analysis": analysis.content},
                "messages": [{"role": "assistant", "content": analysis.content}]
            }
            
        except Exception as e:
            logger.error(f"Error analyzing code: {str(e)}")
            return {"messages": [{"role": "system", "content": f"Error: {str(e)}"}]}

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
        try:
            # Initialize state with CodeQL finding
            initial_state = {
                "messages": [],
                "context": {},
                "codeql_finding": codeql_finding
            }
            
            # Run the graph
            final_state = self.graph.invoke(initial_state)
            
            return {
                "analysis": final_state.get("context", {}).get("analysis", ""),
                "code_context": final_state.get("context", {}).get("code_context", ""),
                "finding": codeql_finding
            }
            
        except Exception as e:
            logger.error(f"Error in code analysis: {str(e)}")
            return {"error": str(e)}

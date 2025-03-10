from typing import Annotated, Dict, Any
from typing_extensions import TypedDict
from langgraph.graph.message import add_messages

class State(TypedDict):
    messages: Annotated[list, add_messages]
    context: Dict[str, Any]  # Store dependency context and analysis results
    dependency: Dict[str, Any]  # Store the current dependency being analyzed
    dependency_name: str
    vulnerability_info: Dict
    usage_info: Dict
    analysis: Dict
"""
Scanner package for security analysis
"""

# Update imports to use new module structure
from .scan import detect_all_languages, run_codeql_analysis, run_dependency_check
from .agents.code_agent import CodeAnalysisAgent
from .agents.dependency import DependencyAnalysisAgent  # Updated import path

__all__ = [
    'CodeAnalysisAgent',
    'DependencyAnalysisAgent',
    'detect_all_languages',
    'run_codeql_analysis',
    'run_dependency_check'
]

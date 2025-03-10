import os
import re
import logging
from typing import Dict, List, Set
from dataclasses import dataclass
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor
from functools import lru_cache

logger = logging.getLogger(__name__)

@dataclass
class UsageMatch:
    file: str
    line: int
    statement: str

class DependencyUsageAnalyzer:
    # Common file patterns to ignore
    SKIP_DIRS: Set[str] = {'.git', 'node_modules', 'venv', '__pycache__'}
    VALID_EXTENSIONS: Set[str] = {
        '.py', '.js', '.jsx', '.ts', '.tsx', '.java', '.php', '.rb',
        '.json', '.yaml', '.yml', '.xml', '.properties', '.config'
    }

    def __init__(self, repo_path: str):
        self.repo_path = Path(repo_path)
        self._setup_patterns()

    def _setup_patterns(self):
        """Initialize regex patterns for different types of dependency usage"""
        self.import_patterns = {
            'typescript': [
                r"import\s+.*['\"]({name})['\"]",     # import x from 'pkg'
                r"from\s+['\"]({name})['\"]",         # from 'pkg' import x
            ],
            'nodejs': [
                r"require\s*\(\s*['\"]({name})['\"]", # require('pkg')
            ],
            'python': [
                r"import\s+{name}[\s;]",              # import pkg
                r"from\s+{name}[\s;]",                # from pkg import x
            ]
        }

        self.config_patterns = {
            'json_yaml': r"['\"]?{name}['\"]?\s*:",   # "pkg": or pkg:
            'properties': r"{name}=",                  # pkg=value
            'xml': r"<{name}>"                        # <pkg>
        }

    @lru_cache(maxsize=1000)
    def _is_valid_file(self, file_path: str) -> bool:
        """Check if file should be analyzed (cached for performance)"""
        path = Path(file_path)
        return (
            path.suffix in self.VALID_EXTENSIONS and
            not any(skip in path.parts for skip in self.SKIP_DIRS)
        )

    def _compile_patterns(self, name: str) -> Dict[str, List[re.Pattern]]:
        """Compile regex patterns for a specific dependency name"""
        patterns = {
            'import': [],
            'config': []
        }
        
        # Compile import patterns
        for pattern_group in self.import_patterns.values():
            for pattern in pattern_group:
                try:
                    patterns['import'].append(
                        re.compile(pattern.format(name=re.escape(name)), re.MULTILINE)
                    )
                except re.error as e:
                    logger.warning(f"Invalid import pattern for {name}: {e}")

        # Compile config patterns
        for pattern in self.config_patterns.values():
            try:
                patterns['config'].append(
                    re.compile(pattern.format(name=re.escape(name)), re.MULTILINE)
                )
            except re.error as e:
                logger.warning(f"Invalid config pattern for {name}: {e}")

        return patterns

    def _analyze_file(self, file_path: Path, patterns: Dict[str, List[re.Pattern]], name: str) -> Dict:
        """Analyze a single file for dependency usage"""
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()

            result = {
                'import_statements': [],
                'configuration': [],
                'has_dependency': False,
                'content': None
            }

            # Only store content if dependency is found
            if name in content:
                result['has_dependency'] = True
                result['content'] = content

                # Find import statements
                for pattern in patterns['import']:
                    for match in pattern.finditer(content):
                        result['import_statements'].append(UsageMatch(
                            file=str(file_path.relative_to(self.repo_path)),
                            line=content.count('\n', 0, match.start()) + 1,
                            statement=match.group().strip()
                        ))

                # Find configuration usage
                for pattern in patterns['config']:
                    for match in pattern.finditer(content):
                        result['configuration'].append(UsageMatch(
                            file=str(file_path.relative_to(self.repo_path)),
                            line=content.count('\n', 0, match.start()) + 1,
                            statement=match.group().strip()
                        ))

            return result

        except Exception as e:
            logger.debug(f"Error analyzing file {file_path}: {str(e)}")
            return None

    def analyze_usage(self, name: str) -> Dict:
        """
        Find how the dependency is used in the codebase.
        Uses parallel processing for faster analysis.
        """
        if not self.repo_path.exists():
            logger.warning("Repository path does not exist")
            return {"error": "Repository path does not exist"}

        try:
            patterns = self._compile_patterns(name)
            usage_info = {
                "import_statements": [],
                "configuration": [],
                "files_analyzed": 0,
                "file_contents": {}
            }

            # Get list of files to analyze
            files_to_analyze = [
                f for f in self.repo_path.rglob('*')
                if f.is_file() and self._is_valid_file(str(f))
            ]

            # Process files in parallel
            with ThreadPoolExecutor() as executor:
                future_to_file = {
                    executor.submit(self._analyze_file, f, patterns, name): f
                    for f in files_to_analyze
                }

                for future in future_to_file:
                    result = future.result()
                    if result:
                        usage_info['files_analyzed'] += 1
                        if result['has_dependency']:
                            file_path = str(future_to_file[future].relative_to(self.repo_path))
                            usage_info['file_contents'][file_path] = result['content']
                            usage_info['import_statements'].extend(result['import_statements'])
                            usage_info['configuration'].extend(result['configuration'])

            logger.info(
                f"Completed usage analysis for {name}. "
                f"Found {len(usage_info['import_statements'])} imports in "
                f"{len(usage_info['file_contents'])} relevant files"
            )
            return usage_info

        except Exception as e:
            logger.error(f"Error analyzing dependency usage: {str(e)}", exc_info=True)
            return {"error": str(e)} 
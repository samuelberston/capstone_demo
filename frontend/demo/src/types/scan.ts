export interface Scan {
  id: number;
  repository_url: string;
  branch: string;
  commit_hash: string;
  scan_date: string;
  status: string;
  current_step?: string;
  progress_percentage?: number;
  status_message?: string;
  error_message?: string;
  codeql_findings: CodeQLFinding[];
  dependency_findings: DependencyCheckFinding[];
}

export interface CodeQLFinding {
  id: number;
  scan_id: number;
  rule_id: string;
  message: string;
  file_path: string;
  start_line: number;
  llm_verification: string;
  llm_exploitability: string;
  llm_priority: string;
  code_context?: string;
  analysis?: {
    description: string;
    dataFlow: string;
    impact: string;
    recommendations: string[];
    vulnerableCode: string;
  };
}

export interface DependencyCheckFinding {
  id: number;
  scan_id: number;
  dependency_name: string;
  dependency_version: string;
  vulnerability_id: string;
  vulnerability_name: string;
  severity: string;
  cvss_score: number;
  description: string;
  llm_exploitability: string;
  llm_priority: string;
  analysis?: {
    description: string;
    recommendations: string[];
  };
} 
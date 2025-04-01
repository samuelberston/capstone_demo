/* eslint-disable @typescript-eslint/no-explicit-any */
export interface Scan {
  id: number;
  repository_url: string;
  branch: string;
  commit_hash: string;
  scan_date: string;
  status: 'pending' | 'running' | 'completed' | 'failed';
  current_step?: 'cloning' | 'language_detection' | 'scanning';
  progress_percentage: number;
  status_message?: string;
  error_message?: string;
  // Add new fields for parallel task tracking
  codeql_status: 'pending' | 'running' | 'completed' | 'failed';
  dependency_status: 'pending' | 'running' | 'completed' | 'failed';
  start_time?: string;
  codeql_findings: CodeQLFinding[];
  dependency_findings: DependencyCheckFinding[];
}

export interface ScanProgressDetails {
  current_step: string;
  step_progress: number;
  total_steps: number;
  current_step_details: {
    dependencies_analyzed?: number;
    total_dependencies?: number;
    vulnerabilities_found?: number;
    estimated_time_remaining?: string;
  };
  step_history: {
    step: string;
    start_time: string;
    end_time?: string;
    status: 'completed' | 'running' | 'failed';
  }[];
}

export interface CodeQLFinding {
  id: number;
  scan_id: number;
  rule_id: string;
  rule_index?: number;
  message: string;
  file_path: string;
  start_line: number;
  start_column?: number;
  end_column?: number;
  fingerprint?: string;
  llm_verification: string;
  llm_exploitability: string;
  llm_remediation?: string;
  llm_priority: string;
  code_context?: string;
  analysis?: {
    description: string;
    dataFlow: string;
    impact: string;
    recommendations: string[];
    vulnerableCode: string;
  };
  raw_data?: any;
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
  code_context?: string;
  analysis: {
    description: string;
    dataFlow?: string;
    recommendations: string[];
    vulnerableCode?: string;
  };
} 
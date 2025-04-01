'use client'

import { useState, useEffect } from 'react'
import { Toaster, toast } from 'react-hot-toast'
import criticalFindings from './juice-shop-critical-findings.json'
import { Scan } from '@/types/scan'
import { ScanProgress } from '@/components/ScanProgress'
import { CodeQLFinding, DependencyCheckFinding } from '@/types/scan'

// Convert the JSON findings into the expected Scan format
const dummyData: Scan[] = [{
  id: 1,
  repository_url: "https://github.com/juice-shop/juice-shop",
  branch: "main", 
  commit_hash: "9e4b255",
  scan_date: new Date().toISOString(),
  status: "completed",
  codeql_status: "completed",
  dependency_status: "completed",
  progress_percentage: 100,
  codeql_findings: criticalFindings.results.map(finding => ({
    id: 1,
    scan_id: 1,
    rule_id: finding.ruleId,
    message: finding.message,
    file_path: finding.location,
    start_line: finding.raw_finding.locations?.[0]?.physicalLocation?.region?.startLine || 0,
    llm_verification: finding.analysis.description,
    llm_exploitability: finding.analysis.impact,
    llm_priority: "High priority",
    code_context: finding.code_context || finding.analysis.vulnerableCode || "No code context available",
    analysis: {
      description: finding.analysis.description,
      dataFlow: finding.analysis.dataFlow,
      impact: finding.analysis.impact,
      recommendations: finding.analysis.recommendations,
      vulnerableCode: finding.analysis.vulnerableCode || finding.code_context || "No vulnerable code available"
    }
  })),
  dependency_findings: [
    {
      id: 1,
      scan_id: 1,
      dependency_name: "express-jwt",
      dependency_version: "0.1.3",
      vulnerability_id: "CVE-2020-15084",
      vulnerability_name: "Authorization Bypass in express-jwt",
      severity: "CRITICAL",
      cvss_score: 9.1,
      description: "In express-jwt (NPM package) up and including version 5.3.3, the algorithms entry to be specified in the configuration is not being enforced. When algorithms is not specified in the configuration, with the combination of jwks-rsa, it may lead to authorization bypass.",
      llm_exploitability: "High - The vulnerability allows attackers to bypass authorization checks when using jwks-rsa as the secret without proper algorithm validation.",
      llm_priority: "Critical",
      code_context: "const checkJwt = jwt({\n  secret: jwksRsa.expressJwtSecret({\n    rateLimit: true,\n    jwksRequestsPerMinute: 5,\n    jwksUri: `https://${DOMAIN}/.well-known/jwks.json`\n  }),\n  // Missing algorithms configuration\n  audience: process.env.AUDIENCE,\n  issuer: `https://${DOMAIN}/`\n});",
      analysis: {
        description: "The vulnerability exists in the express-jwt middleware where it fails to enforce algorithm validation when using jwks-rsa as the secret. This can lead to authorization bypass attacks.",
        dataFlow: "The vulnerability occurs in the JWT verification process where the algorithms parameter is not enforced. This allows attackers to potentially bypass authorization by using different signing algorithms than intended.",
        recommendations: [
          "Specify algorithms in the express-jwt configuration",
          "Update to version 6.0.0 or later",
          "Use proper algorithm validation with jwks-rsa",
          "Implement proper error handling for invalid tokens"
        ],
        vulnerableCode: "const checkJwt = jwt({\n  secret: jwksRsa.expressJwtSecret({\n    rateLimit: true,\n    jwksRequestsPerMinute: 5,\n    jwksUri: `https://${DOMAIN}/.well-known/jwks.json`\n  }),\n  // Missing algorithms configuration\n  audience: process.env.AUDIENCE,\n  issuer: `https://${DOMAIN}/`\n});"
      }
    },
    {
      id: 2,
      scan_id: 1,
      dependency_name: "lodash",
      dependency_version: "4.17.15",
      vulnerability_id: "CVE-2019-10744",
      vulnerability_name: "Prototype Pollution in lodash",
      severity: "HIGH",
      cvss_score: 7.5,
      description: "A vulnerability was found in lodash where the merge, mergeWith, and defaultsDeep functions could be tricked into adding or modifying properties of Object.prototype.",
      llm_exploitability: "High - Attackers can pollute the Object prototype, potentially leading to denial of service or remote code execution.",
      llm_priority: "High",
      code_context: "const _ = require('lodash');\n\n// Vulnerable code\nconst userInput = JSON.parse(req.body);\nconst config = _.merge({}, userInput);\n\n// This could pollute Object.prototype\nconst result = _.defaultsDeep({}, userInput);",
      analysis: {
        description: "The vulnerability exists in lodash's merge functions where it fails to properly validate input objects, allowing prototype pollution attacks.",
        dataFlow: "The vulnerability occurs when user-controlled input is passed to lodash's merge functions without proper validation. The merge operation can modify Object.prototype if the input contains specially crafted properties.",
        recommendations: [
          "Update to version 4.17.16 or later",
          "Use Object.freeze() to prevent prototype modification",
          "Implement proper input validation",
          "Consider using alternative libraries with better security"
        ],
        vulnerableCode: "const _ = require('lodash');\n\n// Vulnerable code\nconst userInput = JSON.parse(req.body);\nconst config = _.merge({}, userInput);\n\n// This could pollute Object.prototype\nconst result = _.defaultsDeep({}, userInput);"
      }
    }
  ]
}]

const API_BASE = 'http://localhost:5001';

// Move fetchScans to top level, before resetRunningScans
async function fetchScans() {
  try {
    const response = await fetch(`${API_BASE}/scans`);
    if (!response.ok) throw new Error('Failed to fetch scans');
    const data = await response.json();
    return data.scans.sort((a: Scan, b: Scan) => 
      new Date(b.scan_date).getTime() - new Date(a.scan_date).getTime()
    );
  } catch (error) {
    console.error('Error fetching scans:', error);
    return [];
  }
}

// Add this function at the top level
async function startScanRequest(repositoryUrl: string) {
  const response = await fetch(`${API_BASE}/analyze`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({ github_url: repositoryUrl }),
  });
  if (!response.ok) {
    throw new Error('Failed to start scan');
  }
  return response.json();
}

// Add this function near the other API functions
async function resetRunningScans() {
  try {
    const response = await fetch(`${API_BASE}/scans/reset`, {
      method: 'POST',
    });
    if (!response.ok) throw new Error('Failed to reset scans');
    
    // Refresh the scans list
    const updatedScans = await fetchScans();
    return updatedScans;
  } catch (error) {
    console.error('Error resetting scans:', error);
    throw error;
  }
}

// Add this component
const LoadingSpinner = () => (
  <div className="flex items-center justify-center p-4">
    <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-blue-500"></div>
  </div>
);

// Add this helper function
const getScanStatus = (scan: Scan) => {
  // If overall status is failed, return failed
  if (scan.status === 'failed') return 'failed';
  
  // If both analyses are complete, return completed
  if (scan.codeql_status === 'completed' && scan.dependency_status === 'completed') {
    return 'completed';
  }
  
  // If either analysis is running, return running with details
  if (scan.codeql_status === 'running' || scan.dependency_status === 'running') {
    const details = [];
    if (scan.codeql_status === 'running') details.push('CodeQL');
    if (scan.dependency_status === 'running') details.push('Dependency');
    return `running (${details.join(', ')})`;
  }
  
  return scan.status;
};

export default function Dashboard() {
  const [selectedScan, setSelectedScan] = useState<Scan | null>(null)
  const [isModalOpen, setIsModalOpen] = useState(false)
  const [activeTab, setActiveTab] = useState<'code' | 'dependency'>('code')
  const [expandedFinding, setExpandedFinding] = useState<number | null>(null)
  const [newScanData, setNewScanData] = useState({
    repositoryUrl: '',
    agents: {
      code: true,
      dependency: true
    }
  })
  const [isMounted, setIsMounted] = useState(false)
  const [scans, setScans] = useState<Scan[]>([])
  const [isLoading, setIsLoading] = useState(true)
  
  useEffect(() => {
    setIsMounted(true)
  }, [])

  // Update the useEffect hook that loads scans
  useEffect(() => {
    async function loadScans() {
      try {
        const fetchedScans = await fetchScans();
        // Combine fetched scans with dummy data
        const combinedScans = [...fetchedScans, ...dummyData];
        setScans(combinedScans);
        setIsLoading(false);

        // If there are running scans, start polling
        if (fetchedScans.some(scan => scan.status === 'running')) {
          startPolling();
        }
      } catch (error) {
        console.error('Error loading scans:', error);
        // Fallback to dummy data on error
        setScans(dummyData);
        setIsLoading(false);
      }
    }
    
    loadScans();
    
    // Cleanup polling on unmount
    return () => {
      if (window.pollInterval) {
        clearInterval(window.pollInterval);
      }
    };
  }, []);

  // Update the startPolling function
  const startPolling = () => {
    // Clear any existing interval
    if (window.pollInterval) {
      clearInterval(window.pollInterval);
    }
    
    // Start a new polling interval
    window.pollInterval = setInterval(async () => {
      try {
        const fetchedScans = await fetchScans();
        // Combine new fetched scans with dummy data
        const combinedScans = [...fetchedScans, ...dummyData];
        setScans(combinedScans);
        
        // Stop polling if no scans are running
        if (!fetchedScans.some((scan: Scan) => scan.status === 'running')) {
          clearInterval(window.pollInterval);
        }
      } catch (error) {
        console.error('Error polling scans:', error);
        // Don't clear interval on error, keep trying
      }
    }, 2000);
  };

  const getPriorityLevel = (priority: string): string => {
    if (priority.toLowerCase().includes('high')) return 'High'
    if (priority.toLowerCase().includes('medium')) return 'Medium'
    if (priority.toLowerCase().includes('low')) return 'Low'
    if (priority.toLowerCase().includes('critical')) return 'Critical'
    return 'Medium'
  }

  const getVerificationColor = (verification: string | null | undefined): string => {
    if (!verification) return 'bg-yellow-500/15 text-yellow-500'
    if (verification.toLowerCase().includes('true')) return 'bg-green-500/15 text-green-500'
    if (verification.toLowerCase().includes('false')) return 'bg-red-500/15 text-red-500'
    return 'bg-yellow-500/15 text-yellow-500'
  }

  const getExploitabilityColor = (exploitability: string): string => {
    if (exploitability.toLowerCase().includes('high')) return 'bg-red-500/15 text-red-500'
    if (exploitability.toLowerCase().includes('medium')) return 'bg-yellow-500/15 text-yellow-500'
    if (exploitability.toLowerCase().includes('low')) return 'bg-blue-500/15 text-blue-500'
    return 'bg-gray-500/15 text-gray-500'
  }

  const getVerificationText = (verification: string | null | undefined): string => {
    if (!verification) return 'Unknown'
    if (verification.toLowerCase().includes('true')) return 'True Positive'
    if (verification.toLowerCase().includes('false')) return 'False Positive'
    return 'Unknown'
  }

  const getExploitabilityText = (exploitability: string): string => {
    if (exploitability.toLowerCase().includes('high')) return 'Exploitable'
    if (exploitability.toLowerCase().includes('medium')) return 'Partially Exploitable'
    if (exploitability.toLowerCase().includes('low')) return 'Not Exploitable'
    return 'Unknown'
  }

  const handleScanClick = (scan: Scan) => {
    setSelectedScan(selectedScan?.id === scan.id ? null : scan)
  }

  const handleStartScan = async (e: React.FormEvent) => {
    e.preventDefault()
    const toastId = toast.loading('Starting scan...'); 
    
    try {
      // Make the API call
      const newScan = await startScanRequest(newScanData.repositoryUrl);
      
      // Immediately fetch and update scans to show the new one
      const fetchedScans = await fetchScans();
      const combinedScans = [...fetchedScans, ...dummyData];
      setScans(combinedScans);
      
      // Start polling
      startPolling();
      
      // Dismiss the loading toast and show success
      toast.dismiss(toastId);
      toast.success(`Scan started on ${newScanData.repositoryUrl.split('/').slice(-2).join('/')}`, {
        style: {
          background: '#1f2937',
          color: '#fff',
          padding: '16px',
          fontSize: '1.1rem',
          borderRadius: '10px',
          border: '1px solid #374151',
        },
        duration: 4000,
      });

      // Close modal and reset form
      setIsModalOpen(false);
      setNewScanData({
        repositoryUrl: '',
        agents: { code: true, dependency: true }
      });

    } catch (error) {
      toast.dismiss(toastId);
      toast.error(`Failed to start scan: ${error instanceof Error ? error.message : 'Unknown error'}`);
    }
  }

  const handleFindingClick = (index: number) => {
    setExpandedFinding(prev => prev === index ? null : index);
  }

  const formatDate = (dateString: string) => {
    if (!isMounted) {
      return dateString;
    }
    return new Date(dateString).toLocaleDateString();
  }

  const clearFailedScans = async () => {
    try {
      const response = await fetch(`${API_BASE}/scans/clear-failed`, {
        method: 'POST',
      });
      if (!response.ok) throw new Error('Failed to clear scans');
      
      // Refresh the scans list
      const updatedScans = await fetchScans();
      setScans(updatedScans.length > 0 ? updatedScans : []);
      
      toast.success('Successfully cleared failed scans');
    } catch (error) {
      toast.error('Failed to clear scans');
      console.error('Error clearing scans:', error);
    }
  };

  return (
    <div className="p-6 max-w-7xl mx-auto">
      {/* Toaster with updated styling */}
      <Toaster 
        position="top-right"
        toastOptions={{
          success: {
            iconTheme: {
              primary: '#10B981', // Green color for success icon
              secondary: '#fff',
            },
          },
        }}
      />
      
      <h1 className="text-3xl font-bold mb-8 text-white text-center">Security Scan Dashboard</h1>
      
      {/* Scans Section Header with Buttons */}
      <div className="mb-12 text-center flex justify-center gap-4">
        <button
          onClick={() => setIsModalOpen(true)}
          className="px-8 py-4 text-lg font-semibold text-white rounded-xl
            bg-gradient-to-r from-blue-500 to-blue-700 hover:from-blue-600 hover:to-blue-800
            transform hover:scale-105 transition-all duration-200
            border-2 border-blue-400 shadow-lg hover:shadow-blue-500/30"
        >
          Start New Security Scan
        </button>
        
        <button
          onClick={clearFailedScans}
          className="px-8 py-4 text-lg font-semibold text-white rounded-xl
            bg-gradient-to-r from-red-500 to-red-700 hover:from-red-600 hover:to-red-800
            transform hover:scale-105 transition-all duration-200
            border-2 border-red-400 shadow-lg hover:shadow-red-500/30"
        >
          Clear Failed Scans
        </button>

        <button
          onClick={async () => {
            try {
              await resetRunningScans();
              toast.success('Successfully reset running scans');
              // Refresh scans list
              const updatedScans = await fetchScans();
              setScans(updatedScans.length > 0 ? updatedScans : []);
            } catch (error) {
              toast.error(`Failed to reset running scans: ${error instanceof Error ? error.message : 'Unknown error'}`);
            }
          }}
          className="px-8 py-4 text-lg font-semibold text-white rounded-xl
            bg-gradient-to-r from-yellow-500 to-yellow-700 hover:from-yellow-600 hover:to-yellow-800
            transform hover:scale-105 transition-all duration-200
            border-2 border-yellow-400 shadow-lg hover:shadow-yellow-500/30"
        >
          Reset Running Scans
        </button>
      </div>

      {/* New Scan Modal */}
      {isModalOpen && (
        <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50">
          <div className="bg-gray-800 rounded-xl p-8 w-full max-w-md border border-gray-700 shadow-xl">
            <h3 className="text-2xl font-semibold text-white mb-6 text-center">Start New Security Scan</h3>
            <form onSubmit={handleStartScan}>
              <div className="mb-6">
                <label htmlFor="repositoryUrl" className="block text-sm font-medium text-gray-300 mb-2">
                  GitHub Repository URL
                </label>
                <input
                  type="text"
                  id="repositoryUrl"
                  value={newScanData.repositoryUrl}
                  onChange={(e) => setNewScanData({...newScanData, repositoryUrl: e.target.value})}
                  placeholder="https://github.com/username/repository"
                  className="w-full p-3 rounded-lg bg-gray-700 text-white border border-gray-600 
                    focus:border-blue-500 focus:ring-2 focus:ring-blue-500 focus:ring-opacity-50
                    placeholder-gray-400 transition-all duration-200"
                  required
                />
              </div>
              
              <div className="mb-8">
                <label className="block text-sm font-medium text-gray-300 mb-3">
                  Select Security Scan Types
                </label>
                <div className="grid grid-cols-2 gap-4">
                  <button
                    type="button"
                    onClick={() => setNewScanData({
                      ...newScanData,
                      agents: {...newScanData.agents, code: !newScanData.agents.code}
                    })}
                    className={`p-4 rounded-lg border-2 transition-all duration-200 text-center
                      ${newScanData.agents.code 
                        ? 'border-blue-500 bg-blue-500/20 text-white' 
                        : 'border-gray-600 bg-gray-700 text-gray-300 hover:border-gray-500'}`}
                  >
                    <div className="font-medium mb-1">Code Agent</div>
                    <div className="text-sm opacity-75">CodeQL</div>
                  </button>
                  <button
                    type="button"
                    onClick={() => setNewScanData({
                      ...newScanData,
                      agents: {...newScanData.agents, dependency: !newScanData.agents.dependency}
                    })}
                    className={`p-4 rounded-lg border-2 transition-all duration-200 text-center
                      ${newScanData.agents.dependency 
                        ? 'border-blue-500 bg-blue-500/20 text-white' 
                  
                        : 'border-gray-600 bg-gray-700 text-gray-300 hover:border-gray-500'}`}
                  >
                    <div className="font-medium mb-1">Dependency Agent</div>
                    <div className="text-sm opacity-75">Dependency Check</div>
                  </button>
                </div>
              </div>

              <div className="flex justify-end space-x-4">
                <button
                  type="button"
                  onClick={() => setIsModalOpen(false)}
                  className="px-6 py-3 text-gray-300 hover:text-white transition-colors
                    hover:bg-gray-700 rounded-lg"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  className="px-6 py-3 rounded-lg font-medium
                    bg-gradient-to-r from-blue-500 to-blue-700 
                    hover:from-blue-600 hover:to-blue-800
                    text-white transform hover:scale-105 transition-all duration-200"
                >
                  Start Scan
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* Scans Section Header */}
      <div className="mb-6">
        <h2 className="text-2xl font-semibold text-white">Recent Scans</h2>
      </div>

      {/* Scans List */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6 mb-8">
        {isLoading ? (
          <LoadingSpinner />
        ) : scans.length === 0 ? (
          <div className="text-gray-400 text-center py-8">No scans found</div>
        ) : (
          scans.map((scan) => (
            <div 
              key={scan.id}
              className={`border rounded-lg p-6 transition-all duration-200 
                ${selectedScan?.id === scan.id 
                  ? 'border-blue-500 ring-2 ring-blue-200' 
                  : getScanStatus(scan).startsWith('running')
                    ? 'border-blue-400 animate-[pulse_2s_ease-in-out_infinite] hover:border-blue-300'
                    : getScanStatus(scan).startsWith('completed') && (scan.codeql_findings?.length > 0 || scan.dependency_findings?.length > 0)
                      ? 'hover:border-gray-300 hover:shadow-md cursor-pointer'
                      : 'border-gray-700'}`}
              onClick={() => {
                // Only allow clicking if scan is completed and has findings
                if (getScanStatus(scan).startsWith('completed') && 
                    (scan.codeql_findings?.length > 0 || scan.dependency_findings?.length > 0)) {
                  handleScanClick(scan)
                }
              }}
            >
              <div className="flex items-start justify-between mb-4">
                <div className="flex-1">
                  <h2 className="font-semibold text-lg text-white truncate">{scan.repository_url.split('/').slice(-2).join('/')}</h2>
                  <p className="text-sm text-gray-400">Branch: {scan.branch}</p>
                </div>
                <span className={`text-sm px-3 py-1 rounded-full flex items-center gap-2 ${
                  getScanStatus(scan).startsWith('completed') ? 'bg-green-500/15 text-green-500 font-medium' : 
                  getScanStatus(scan).startsWith('running') ? 'bg-blue-500/15 text-blue-500 font-medium animate-pulse' : 
                  'bg-yellow-500/15 text-yellow-500 font-medium'
                }`}>
                  {getScanStatus(scan).startsWith('running') && (
                    <div className="animate-spin rounded-full h-3 w-3 border-b-2 border-blue-500"></div>
                  )}
                  {getScanStatus(scan)}
                </span>
              </div>
              {scan.status === 'running' && scan.status_message && (
                <p className="text-sm text-gray-400 mt-2">
                  {scan.status_message}
                </p>
              )}
              <div className="space-y-1">
                <p className="text-sm text-gray-600">
                  <span className="inline-block w-20">Commit:</span>
                  {scan.commit_hash ? (
                    <span className="font-mono">{scan.commit_hash}</span>
                  ) : getScanStatus(scan).startsWith('running') ? (
                    <span className="text-gray-400">Fetching...</span>
                  ) : (
                    <span className="text-gray-400">N/A</span>
                  )}
                </p>
                <p className="text-sm text-gray-600">
                  <span className="inline-block w-20">Scanned:</span>
                  <time dateTime={scan.scan_date}>
                    {formatDate(scan.scan_date)}
                  </time>
                </p>
              </div>
              <div className="mt-4 flex gap-3">
                <div className="bg-red-500/15 text-red-500 font-medium px-3 py-1 rounded-full text-sm">
                  {(scan.codeql_findings || []).length} CodeQL
                </div>
                <div className="bg-orange-500/15 text-orange-500 font-medium px-3 py-1 rounded-full text-sm">
                  {(scan.dependency_findings || []).length} Dependencies
                </div>
              </div>

              {/* Add a message when scan is completed but has no findings */}
              {getScanStatus(scan).startsWith('completed') && 
               !scan.codeql_findings?.length && 
               !scan.dependency_findings?.length && (
                <div className="mt-4 text-sm text-gray-400">
                  No vulnerabilities found
                </div>
              )}

              {/* Add progress bar for running scans */}
              {scan.status === 'running' && (
                <div className="mt-4">
                  <ScanProgress scan={scan} />
                </div>
              )}
            </div>
          ))
        )}
      </div>

      {/* Selected Scan Details */}
      {selectedScan && (
        <div className="space-y-8">
          {/* Tabs */}
          <div className="border-b border-gray-700">
            <div className="flex space-x-8">
              <button
                onClick={() => setActiveTab('code')}
                className={`py-4 px-4 relative ${
                  activeTab === 'code'
                    ? 'text-blue-500'
                    : 'text-gray-400 hover:text-gray-300'
                }`}
              >
                <span className="text-lg font-semibold">
                  Code Vulnerabilities ({(selectedScan.codeql_findings || []).length})
                </span>
                {activeTab === 'code' && (
                  <span className="absolute bottom-0 left-0 w-full h-0.5 bg-blue-500"></span>
                )}
              </button>
              <button
                onClick={() => setActiveTab('dependency')}
                className={`py-4 px-4 relative ${
                  activeTab === 'dependency'
                    ? 'text-blue-500'
                    : 'text-gray-400 hover:text-gray-300'
                }`}
              >
                <span className="text-lg font-semibold">
                  Dependency Vulnerabilities ({(selectedScan.dependency_findings || []).length})
                </span>
                {activeTab === 'dependency' && (
                  <span className="absolute bottom-0 left-0 w-full h-0.5 bg-blue-500"></span>
                )}
              </button>
            </div>
          </div>

          {/* Tab Content */}
          <div className="mt-6">
            {activeTab === 'code' && (
              <div className="overflow-hidden rounded-lg border border-gray-700">
                {/* Table Header */}
                <div className="grid grid-cols-12 bg-gray-800 text-gray-300 text-sm font-medium">
                  <div className="col-span-4 p-4">Vulnerability</div>
                  <div className="col-span-3 p-4">Location</div>
                  <div className="col-span-2 p-4">Verification</div>
                  <div className="col-span-2 p-4">Exploitability</div>
                  <div className="col-span-1 p-4">Priority</div>
                </div>
                
                {/* Table Rows */}
                <div className="divide-y divide-gray-700">
                  {(selectedScan.codeql_findings || []).map((finding, index) => (
                    <div key={index}>
                      {/* Row */}
                      <div 
                        className="grid grid-cols-12 text-sm hover:bg-gray-800/50 cursor-pointer transition-colors"
                        onClick={() => handleFindingClick(index)}
                      >
                        <div className="col-span-4 p-4">
                          <div className="font-medium text-white">{finding.rule_id}</div>
                          <div className="text-gray-400 truncate max-w-xs">{finding.message}</div>
                        </div>
                        <div className="col-span-3 p-4 font-mono text-gray-400">
                          {finding.file_path}:{finding.start_line}
                        </div>
                        <div className="col-span-2 p-4">
                          <span className={`px-2 py-1 rounded-full text-xs font-medium ${getVerificationColor(finding.llm_verification)}`}>
                            {getVerificationText(finding.llm_verification)}
                          </span>
                        </div>
                        <div className="col-span-2 p-4">
                          <span className={`px-2 py-1 rounded-full text-xs font-medium ${getExploitabilityColor(finding.llm_exploitability)}`}>
                            {getExploitabilityText(finding.llm_exploitability)}
                          </span>
                        </div>
                        <div className="col-span-1 p-4">
                          <span className={`px-2 py-1 rounded-full text-xs font-medium ${
                            getPriorityLevel(finding.llm_priority) === 'Critical' ? 'bg-red-500/15 text-red-500' : 
                            getPriorityLevel(finding.llm_priority) === 'High' ? 'bg-red-500/15 text-red-500' : 
                            getPriorityLevel(finding.llm_priority) === 'Medium' ? 'bg-yellow-500/15 text-yellow-500' : 
                            'bg-blue-500/15 text-blue-500'
                          }`}>
                            {getPriorityLevel(finding.llm_priority)}
                          </span>
                        </div>
                      </div>
                      
                      {/* Expanded Details */}
                      {expandedFinding === index && (
                        <div className="p-6 bg-gray-800/30 border-t border-gray-700">
                          <div className="grid grid-cols-1 gap-6">
                            {/* Vulnerable Code Section */}
                            <div className="bg-gray-800/50 rounded-lg p-4 border border-gray-700">
                              <h4 className="text-lg font-medium text-gray-200 mb-3">Vulnerable Code</h4>
                              <pre className="bg-black p-4 rounded-lg overflow-x-auto">
                                <code className="text-sm font-mono text-gray-300">
                                  {finding.code_context || finding.analysis?.vulnerableCode || "No code context available"}
                                </code>
                              </pre>
                            </div>

                            {/* Analysis Grid - Moved after code */}
                            <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
                              <div className="bg-gray-800/50 rounded-lg p-4 border border-gray-700">
                                <h4 className="text-lg font-medium text-gray-200 mb-2">Description</h4>
                                <div className="relative">
                                  <div 
                                    id={`${index}-description-content`}
                                    className="text-gray-300"
                                  >
                                    {finding.analysis?.description || 
                                      (activeTab === 'code' 
                                        ? (finding as unknown as CodeQLFinding).message
                                        : (finding as unknown as DependencyCheckFinding).description)
                                    }
                                  </div>
                                </div>
                              </div>
                              
                              <div className="bg-gray-800/50 rounded-lg p-4 border border-gray-700">
                                <div className="flex items-center gap-2 mb-2">
                                  <h4 className="text-lg font-medium text-gray-200">Exploitability</h4>
                                  <span className={`px-3 py-1 rounded-full text-sm font-medium ${getExploitabilityColor(finding.llm_exploitability)}`}>
                                    {getExploitabilityText(finding.llm_exploitability)}
                                  </span>
                                </div>
                                <div className="relative">
                                  <div 
                                    id={`${index}-exploitability-content`}
                                    className="text-gray-300"
                                  >
                                    {finding.llm_exploitability}
                                  </div>
                                </div>
                              </div>
                            </div>

                            {/* Data Flow Section */}
                            <div className="bg-gray-800/50 rounded-lg p-4 border border-gray-700">
                              <h4 className="text-lg font-medium text-gray-200 mb-3">Data Flow</h4>
                              <div className="relative">
                                <div 
                                  id={`${index}-dataflow-content`}
                                  className="text-gray-300 whitespace-pre-wrap"
                                >
                                  {finding.analysis?.dataFlow || "No data flow information available"}
                                </div>
                              </div>
                            </div>

                            {/* Recommendations Section */}
                            {finding.analysis?.recommendations && (
                              <div className="bg-gray-800/50 rounded-lg p-4 border border-gray-700">
                                <h4 className="text-lg font-medium text-gray-200 mb-3">Recommendations</h4>
                                <div className="relative">
                                  <div 
                                    id={`${index}-recommendations-content`}
                                    className="space-y-2"
                                  >
                                    <ul className="list-disc list-inside space-y-2">
                                      {finding.analysis.recommendations.map((rec, idx) => (
                                        <li key={idx} className="text-gray-300">{rec}</li>
                                      ))}
                                    </ul>
                                  </div>
                                </div>
                              </div>
                            )}
                          </div>
                        </div>
                      )}
                    </div>
                  ))}
                </div>
              </div>
            )}

            {activeTab === 'dependency' && (
              <div className="overflow-hidden rounded-lg border border-gray-700">
                {/* Table Header */}
                <div className="grid grid-cols-12 bg-gray-800 text-gray-300 text-sm font-medium">
                  <div className="col-span-4 p-4">Vulnerability</div>
                  <div className="col-span-3 p-4">Dependency</div>
                  <div className="col-span-2 p-4">Severity</div>
                  <div className="col-span-2 p-4">CVSS Score</div>
                  <div className="col-span-1 p-4">Priority</div>
                </div>
                
                {/* Table Rows */}
                <div className="divide-y divide-gray-700">
                  {(selectedScan.dependency_findings || []).map((finding, index) => (
                    <div key={index}>
                      {/* Row */}
                      <div 
                        className="grid grid-cols-12 text-sm hover:bg-gray-800/50 cursor-pointer transition-colors"
                        onClick={() => handleFindingClick(index)}
                      >
                        <div className="col-span-4 p-4">
                          <div className="font-medium text-white">{finding.vulnerability_name}</div>
                          <div className="text-gray-400">{finding.vulnerability_id}</div>
                        </div>
                        <div className="col-span-3 p-4 font-mono text-gray-400">
                          {finding.dependency_name}@{finding.dependency_version}
                        </div>
                        <div className="col-span-2 p-4">
                          <span className={`px-2 py-1 rounded-full text-xs font-medium ${
                            finding.severity === 'CRITICAL' ? 'bg-red-500/15 text-red-500' :
                            finding.severity === 'HIGH' ? 'bg-red-500/15 text-red-500' :
                            finding.severity === 'MEDIUM' ? 'bg-yellow-500/15 text-yellow-500' :
                            'bg-blue-500/15 text-blue-500'
                          }`}>
                            {finding.severity}
                          </span>
                        </div>
                        <div className="col-span-2 p-4">
                          <span className={`px-2 py-1 rounded-full text-xs font-medium ${
                            finding.cvss_score >= 9.0 ? 'bg-red-500/15 text-red-500' :
                            finding.cvss_score >= 7.0 ? 'bg-red-500/15 text-red-500' :
                            finding.cvss_score >= 4.0 ? 'bg-yellow-500/15 text-yellow-500' :
                            'bg-blue-500/15 text-blue-500'
                          }`}>
                            {finding.cvss_score}
                          </span>
                        </div>
                        <div className="col-span-1 p-4">
                          <span className={`px-2 py-1 rounded-full text-xs font-medium ${
                            getPriorityLevel(finding.llm_priority) === 'Critical' ? 'bg-red-500/15 text-red-500' : 
                            getPriorityLevel(finding.llm_priority) === 'High' ? 'bg-red-500/15 text-red-500' : 
                            getPriorityLevel(finding.llm_priority) === 'Medium' ? 'bg-yellow-500/15 text-yellow-500' : 
                            'bg-blue-500/15 text-blue-500'
                          }`}>
                            {getPriorityLevel(finding.llm_priority)}
                          </span>
                        </div>
                      </div>
                      
                      {/* Expanded Details */}
                      {expandedFinding === index && (
                        <div className="p-6 bg-gray-800/30 border-t border-gray-700">
                          <div className="grid grid-cols-1 gap-6">
                            {/* Vulnerable Code Section */}
                            <div className="bg-gray-800/50 rounded-lg p-4 border border-gray-700">
                              <h4 className="text-lg font-medium text-gray-200 mb-3">Vulnerable Code</h4>
                              <pre className="bg-black p-4 rounded-lg overflow-x-auto">
                                <code className="text-sm font-mono text-gray-300">
                                  {finding.code_context || finding.analysis?.vulnerableCode || "No code context available"}
                                </code>
                              </pre>
                            </div>

                            {/* Analysis Grid - Moved after code */}
                            <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
                              <div className="bg-gray-800/50 rounded-lg p-4 border border-gray-700">
                                <h4 className="text-lg font-medium text-gray-200 mb-2">Description</h4>
                                <div className="relative">
                                  <div 
                                    id={`${index}-description-content`}
                                    className="text-gray-300"
                                  >
                                    {finding.analysis?.description || 
                                      (activeTab === 'code' 
                                        ? (finding as unknown as CodeQLFinding).message
                                        : (finding as unknown as DependencyCheckFinding).description)
                                    }
                                  </div>
                                </div>
                              </div>
                              
                              <div className="bg-gray-800/50 rounded-lg p-4 border border-gray-700">
                                <div className="flex items-center gap-2 mb-2">
                                  <h4 className="text-lg font-medium text-gray-200">Exploitability</h4>
                                  <span className={`px-3 py-1 rounded-full text-sm font-medium ${getExploitabilityColor(finding.llm_exploitability)}`}>
                                    {getExploitabilityText(finding.llm_exploitability)}
                                  </span>
                                </div>
                                <div className="relative">
                                  <div 
                                    id={`${index}-exploitability-content`}
                                    className="text-gray-300"
                                  >
                                    {finding.llm_exploitability}
                                  </div>
                                </div>
                              </div>
                            </div>

                            {/* Data Flow Section */}
                            <div className="bg-gray-800/50 rounded-lg p-4 border border-gray-700">
                              <h4 className="text-lg font-medium text-gray-200 mb-3">Data Flow</h4>
                              <div className="relative">
                                <div 
                                  id={`${index}-dataflow-content`}
                                  className="text-gray-300 whitespace-pre-wrap"
                                >
                                  {finding.analysis?.dataFlow || "No data flow information available"}
                                </div>
                              </div>
                            </div>

                            {/* Recommendations Section */}
                            {finding.analysis?.recommendations && (
                              <div className="bg-gray-800/50 rounded-lg p-4 border border-gray-700">
                                <h4 className="text-lg font-medium text-gray-200 mb-3">Recommendations</h4>
                                <div className="relative">
                                  <div 
                                    id={`${index}-recommendations-content`}
                                    className="space-y-2"
                                  >
                                    <ul className="list-disc list-inside space-y-2">
                                      {finding.analysis.recommendations.map((rec, idx) => (
                                        <li key={idx} className="text-gray-300">{rec}</li>
                                      ))}
                                    </ul>
                                  </div>
                                </div>
                              </div>
                            )}
                          </div>
                        </div>
                      )}
                    </div>
                  ))}
                </div>
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  )
}

// Add TypeScript declaration for the window property
declare global {
  interface Window {
    pollInterval: NodeJS.Timeout | undefined;
  }
}
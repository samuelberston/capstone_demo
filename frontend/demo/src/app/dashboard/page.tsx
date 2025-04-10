'use client'

import { useState, useEffect } from 'react'
import { Toaster, toast } from 'react-hot-toast'
import frontendReadyCodeQLFindings from '../../../../../frontend_ready_findings.json' // Use correct JSON
import { Scan, CodeQLFinding, DependencyCheckFinding } from '@/types/scan'
import { ScanProgress } from '@/components/ScanProgress'

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
  codeql_findings: frontendReadyCodeQLFindings as unknown as CodeQLFinding[], // Use JSON, correct cast
  dependency_findings: [] // Remove hardcoded dependency data
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

// At the top of the file after imports, add these type guards:

function isCodeQLFinding(finding: CodeQLFinding | DependencyCheckFinding): finding is CodeQLFinding {
  return finding && 'rule_id' in finding && 'message' in finding;
}

function isDependencyCheckFinding(finding: CodeQLFinding | DependencyCheckFinding): finding is DependencyCheckFinding {
  return finding && 'dependency_name' in finding && 'vulnerability_id' in finding;
}

// Description rendering helper for any finding type
function getDescription(finding: CodeQLFinding | DependencyCheckFinding): string {
  if (finding.analysis?.description) {
    return finding.analysis.description;
  }
  
  if (isCodeQLFinding(finding)) {
    return finding.message;
  }
  
  if (isDependencyCheckFinding(finding)) {
    return finding.description;
  }
  
  return "No description available";
}

// Normalize rule IDs to readable names
function normalizeRuleId(ruleId: string): string {
  // Remove language prefix (js/, py/, java/, etc.)
  const namePart = ruleId.split('/').pop() || ruleId;
  
  // Convert hyphens and underscores to spaces
  const spacedName = namePart.replace(/[-_]/g, ' ');
  
  // Capitalize each word
  return spacedName
    .split(' ')
    .map(word => word.charAt(0).toUpperCase() + word.slice(1))
    .join(' ');
}

const ITEMS_PER_PAGE = 10;

export default function Dashboard() {
  const [selectedScan, setSelectedScan] = useState<Scan | null>(null)
  const [isModalOpen, setIsModalOpen] = useState(false)
  const [activeTab, setActiveTab] = useState<'code' | 'dependency'>('code')
  const [expandedFindingId, setExpandedFindingId] = useState<number | null>(null) // Use ID for pagination
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
  const [codeQLCurrentPage, setCodeQLCurrentPage] = useState(1); // Pagination state
  const [dependencyCurrentPage, setDependencyCurrentPage] = useState(1); // Pagination state
  
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
        if (fetchedScans.some((scan: Scan) => scan.status === 'running')) {
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

  // Updated Priority logic
  const getPriorityLevel = (priority: string | null | undefined): string => {
    if (!priority) return 'Low'; // Default null/undefined to Low
    const lowerPriority = priority.toLowerCase();
    // Check in order of importance
    if (lowerPriority.includes('critical')) return 'Critical';
    if (lowerPriority.includes('high')) return 'High';
    if (lowerPriority.includes('medium')) return 'Medium';
    if (lowerPriority.includes('low')) return 'Low';
    return 'Low'; // Default any unrecognized string to Low
  }

  // Sorting function for priority - uses updated getPriorityLevel
  const sortByPriority = (findings: CodeQLFinding[]): CodeQLFinding[] => {
    return [...findings].sort((a, b) => {
      const priorityOrder: Record<string, number> = { 'Critical': 0, 'High': 1, 'Medium': 2, 'Low': 3 };
      const aPriority = getPriorityLevel(a.llm_priority);
      const bPriority = getPriorityLevel(b.llm_priority);
      return priorityOrder[aPriority] - priorityOrder[bPriority];
    });
  };

  // Sorting function for dependency findings by CVSS score (descending)
  const sortByCVSS = (findings: DependencyCheckFinding[]): DependencyCheckFinding[] => {
    return [...findings].sort((a, b) => {
      return (b.cvss_score || 0) - (a.cvss_score || 0);
    });
  };

  // Updated Verification logic
  const getVerificationColor = (verification: string | null | undefined): string => {
    if (!verification) return 'bg-red-500/15 text-red-500' // Default Unknown to False Positive color
    const lowerVerification = verification.toLowerCase();
    if (lowerVerification.includes('true positive') || lowerVerification.includes('verified')) return 'bg-green-500/15 text-green-500' 
    if (lowerVerification.includes('false positive')) return 'bg-red-500/15 text-red-500'
    return 'bg-red-500/15 text-red-500' // Default unrecognized to False Positive color
  }

  const getVerificationText = (verification: string | null | undefined): string => {
    if (!verification) return 'False Positive' // Default Unknown to False Positive
    const lowerVerification = verification.toLowerCase();
    if (lowerVerification.includes('true positive') || lowerVerification.includes('verified')) return 'True Positive' 
    if (lowerVerification.includes('false positive')) return 'False Positive'
    return 'False Positive' // Default unrecognized to False Positive
  }

  // Updated Exploitability logic (depends on verification)
  const getExploitabilityColor = (
    exploitability: string | null | undefined,
    verificationStatus: string // Added verificationStatus parameter
  ): string => {
    // If False Positive, always treat as Not Exploitable (blue)
    if (verificationStatus === 'False Positive') return 'bg-blue-500/15 text-blue-500';
    
    if (!exploitability) return 'bg-blue-500/15 text-blue-500' // Default null/undefined to Not Exploitable color
    const lowerExploitability = exploitability.toLowerCase()
    if (lowerExploitability.includes('not exploitable')) return 'bg-blue-500/15 text-blue-500'
    if (lowerExploitability.includes('partially')) return 'bg-yellow-500/15 text-yellow-500'
    if (lowerExploitability.includes('exploitable') || lowerExploitability.includes('high')) return 'bg-red-500/15 text-red-500' 
    return 'bg-blue-500/15 text-blue-500' // Default unrecognized to Not Exploitable color
  }

  const getExploitabilityText = (
    exploitability: string | null | undefined,
    verificationStatus: string // Added verificationStatus parameter
  ): string => {
    // If False Positive, always treat as Not Exploitable
    if (verificationStatus === 'False Positive') return 'Not Exploitable';

    if (!exploitability) return 'Not Exploitable' // Default null/undefined to Not Exploitable
    const lowerExploitability = exploitability.toLowerCase()
    if (lowerExploitability.includes('not exploitable')) return 'Not Exploitable'
    if (lowerExploitability.includes('partially')) return 'Partially Exploitable'
    if (lowerExploitability.includes('exploitable') || lowerExploitability.includes('high')) return 'Exploitable' 
    return 'Not Exploitable' // Default unrecognized to Not Exploitable
  }

  const handleScanClick = (scan: Scan) => {
    setSelectedScan(selectedScan?.id === scan.id ? null : scan)
  }

  const handleStartScan = async (e: React.FormEvent) => {
    e.preventDefault()
    const toastId = toast.loading('Starting scan...'); 
    
    try {
      // Make the API call
      await startScanRequest(newScanData.repositoryUrl);
      
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

  // Updated finding click handler for pagination
  const handleFindingClick = (findingId: number) => { 
    setExpandedFindingId(prev => prev === findingId ? null : findingId);
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

  // Stats calculation functions for the charts
  const calculateVerificationStats = (findings: CodeQLFinding[]): {label: string, count: number, color: string}[] => {
    const stats = {
      'True Positive': 0,
      'False Positive': 0
    };
    
    findings.forEach(finding => {
      const verification = getVerificationText(finding.llm_verification);
      if (verification === 'True Positive') stats['True Positive']++;
      else stats['False Positive']++; // Default is False Positive
    });
    
    return [
      { label: 'True Positive', count: stats['True Positive'], color: 'bg-green-500' },
      { label: 'False Positive', count: stats['False Positive'], color: 'bg-red-500' }
    ];
  };
  
  const calculateExploitabilityStats = (findings: CodeQLFinding[]): {label: string, count: number, color: string}[] => {
    const stats = {
      'Exploitable': 0,
      'Partially Exploitable': 0,
      'Not Exploitable': 0
    };
    
    findings.forEach(finding => {
      const verification = getVerificationText(finding.llm_verification); // Get verification status first
      // Pass verification status to getExploitabilityText
      const exploitability = getExploitabilityText(finding.llm_exploitability, verification); 
      
      if (exploitability === 'Exploitable') stats['Exploitable']++;
      else if (exploitability === 'Partially Exploitable') stats['Partially Exploitable']++;
      else stats['Not Exploitable']++; // All others (including False Positives) count as Not Exploitable
    });
    
    return [
      { label: 'Exploitable', count: stats['Exploitable'], color: 'bg-red-500' },
      { label: 'Partially Exploitable', count: stats['Partially Exploitable'], color: 'bg-yellow-500' },
      { label: 'Not Exploitable', count: stats['Not Exploitable'], color: 'bg-blue-500' }
    ];
  };
  
  const calculatePriorityStats = (findings: CodeQLFinding[]): {label: string, count: number, color: string}[] => {
    const stats = {
      'Critical': 0,
      'High': 0,
      'Medium': 0,
      'Low': 0
    };
    
    findings.forEach(finding => {
      const priority = getPriorityLevel(finding.llm_priority);
      stats[priority as keyof typeof stats]++;
    });
    
    return [
      { label: 'Critical', count: stats['Critical'], color: 'bg-red-700' },
      { label: 'High', count: stats['High'], color: 'bg-red-500' },
      { label: 'Medium', count: stats['Medium'], color: 'bg-yellow-500' },
      { label: 'Low', count: stats['Low'], color: 'bg-blue-500' }
    ];
  };

  // Calculate dependency vulnerability stats by severity
  const calculateSeverityStats = (findings: DependencyCheckFinding[]): {label: string, count: number, color: string}[] => {
    const stats = {
      'CRITICAL': 0,
      'HIGH': 0,
      'MEDIUM': 0,
      'LOW': 0
    };
    
    findings.forEach(finding => {
      stats[finding.severity as keyof typeof stats]++;
    });
    
    return [
      { label: 'Critical', count: stats['CRITICAL'], color: 'bg-red-700' },
      { label: 'High', count: stats['HIGH'], color: 'bg-red-500' },
      { label: 'Medium', count: stats['MEDIUM'], color: 'bg-yellow-500' },
      { label: 'Low', count: stats['LOW'], color: 'bg-blue-500' }
    ];
  };
  
  // Bar Chart Component
  const BarChart = ({ 
    data, 
    title 
  }: { 
    data: {label: string, count: number, color: string}[], 
    title: string 
  }) => {
    // Calculate total for percentage
    const total = data.reduce((sum, item) => sum + item.count, 0);
    
    // Filter out zero counts
    const filteredData = data.filter(item => item.count > 0);
    
    return (
      <div className="bg-gray-800/50 rounded-lg p-4 border border-gray-700">
        <h4 className="text-lg font-medium text-gray-200 mb-3">{title}</h4>
        
        {total > 0 ? (
          <>
            {/* Single bar with segments */}
            <div className="h-8 w-full bg-gray-700 rounded-lg overflow-hidden flex mb-4">
              {filteredData.map((item, idx) => (
                <div 
                  key={idx}
                  className={`${item.color} h-full`}
                  style={{ width: `${(item.count / total) * 100}%` }}
                  title={`${item.label}: ${item.count} (${Math.round((item.count / total) * 100)}%)`}
                />
              ))}
            </div>
            
            {/* Legend */}
            <div className="flex flex-wrap gap-3">
              {filteredData.map((item, idx) => (
                <div key={idx} className="flex items-center gap-2">
                  <div className={`w-3 h-3 rounded-sm ${item.color}`}></div>
                  <span className="text-sm text-gray-400">{item.label} ({item.count})</span>
                </div>
              ))}
            </div>
          </>
        ) : (
          <div className="text-sm text-gray-400 text-center py-2">No data available</div>
        )}
      </div>
    );
  };

  // CodeQL findings pre-processing and sorting
  const processedCodeQLFindings = (selectedScan?.codeql_findings || []).map(finding => {
    const verification = getVerificationText(finding.llm_verification);
    const originalPriority = getPriorityLevel(finding.llm_priority);

    // Rule: If False Positive, downgrade Critical/High to Medium
    if (verification === 'False Positive' && (originalPriority === 'Critical' || originalPriority === 'High')) {
      return { ...finding, llm_priority: 'Medium' };
    }
    
    return finding; // Keep original finding if no rule matches
  });

  const sortedCodeQLFindings = sortByPriority(processedCodeQLFindings); // Sort the processed findings

  // Dependency findings display with sorting by CVSS score
  const sortedDependencyFindings = selectedScan ? sortByCVSS(selectedScan.dependency_findings || []) : [];

  // --- Pagination Logic ---
  // CodeQL Pagination
  const totalCodeQLPages = Math.ceil(sortedCodeQLFindings.length / ITEMS_PER_PAGE);
  const codeQLStartIndex = (codeQLCurrentPage - 1) * ITEMS_PER_PAGE;
  const codeQLEndIndex = codeQLStartIndex + ITEMS_PER_PAGE;
  const paginatedCodeQLFindings = sortedCodeQLFindings.slice(codeQLStartIndex, codeQLEndIndex);

  const handleCodeQLPrev = () => setCodeQLCurrentPage(prev => Math.max(prev - 1, 1));
  const handleCodeQLNext = () => setCodeQLCurrentPage(prev => Math.min(prev + 1, totalCodeQLPages));

  // Dependency Pagination
  const totalDependencyPages = Math.ceil(sortedDependencyFindings.length / ITEMS_PER_PAGE);
  const dependencyStartIndex = (dependencyCurrentPage - 1) * ITEMS_PER_PAGE;
  const dependencyEndIndex = dependencyStartIndex + ITEMS_PER_PAGE;
  const paginatedDependencyFindings = sortedDependencyFindings.slice(dependencyStartIndex, dependencyEndIndex);

  const handleDependencyPrev = () => setDependencyCurrentPage(prev => Math.max(prev - 1, 1));
  const handleDependencyNext = () => setDependencyCurrentPage(prev => Math.min(prev + 1, totalDependencyPages));
  // --- End Pagination Logic ---

  // Calculate stats for charts (Use processed and sorted arrays)
  const verificationStats = selectedScan ? calculateVerificationStats(processedCodeQLFindings) : [];
  const exploitabilityStats = selectedScan ? calculateExploitabilityStats(processedCodeQLFindings) : []; 
  const priorityStats = selectedScan ? calculatePriorityStats(processedCodeQLFindings) : []; // Use processed findings for priority stats
  const severityStats = selectedScan ? calculateSeverityStats(sortedDependencyFindings) : [];

  // Reset page number when scan selection changes or tab changes
  useEffect(() => {
    setCodeQLCurrentPage(1);
    setDependencyCurrentPage(1);
    setExpandedFindingId(null); // Close expanded finding when scan changes
  }, [selectedScan]);

  useEffect(() => {
    setExpandedFindingId(null); // Close expanded finding when tab changes
  }, [activeTab]);

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
      
      <div className="text-center mb-8">
        <h1 className="text-3xl font-bold text-white">Security Scan Dashboard</h1>
        <p className="text-gray-400 mt-2">Powered by LLM agents to help prioritize and triage vulnerabilities in context</p>
      </div>
      
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
              <>
                {/* Stats Charts */}
                <div className="grid grid-cols-1 lg:grid-cols-3 gap-6 mb-8">
                  <BarChart 
                    data={verificationStats} 
                    title="Verification Status" 
                  />
                  <BarChart 
                    data={exploitabilityStats} 
                    title="Exploitability" 
                  />
                  <BarChart 
                    data={priorityStats} 
                    title="Priority Level" 
                  />
                </div>
              
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
                    {paginatedCodeQLFindings.map((finding) => { // Use braces for block scope
                      // Calculate verification status once for reuse
                      const verificationStatus = getVerificationText(finding.llm_verification);
                      
                      return (
                        <div key={finding.id}>
                          {/* Row */}
                          <div 
                            className="grid grid-cols-12 text-sm hover:bg-gray-800/50 cursor-pointer transition-colors"
                            onClick={() => handleFindingClick(finding.id)}
                          >
                            <div className="col-span-4 p-4">
                              <div className="font-medium text-white">{normalizeRuleId(finding.rule_id)}</div>
                              <div className="text-gray-400 truncate max-w-xs">{finding.message}</div>
                            </div>
                            <div className="col-span-3 p-4 font-mono text-gray-400">
                              {finding.file_path}:{finding.start_line}
                            </div>
                            <div className="col-span-2 p-4">
                              <span className={`px-2 py-1 rounded-full text-xs font-medium ${getVerificationColor(finding.llm_verification)}`}>
                                {verificationStatus} {/* Use calculated status */}
                              </span>
                            </div>
                            <div className="col-span-2 p-4">
                              {/* Pass verificationStatus to exploitability helpers */}
                              <span className={`px-2 py-1 rounded-full text-xs font-medium ${getExploitabilityColor(finding.llm_exploitability, verificationStatus)}`}> 
                                {getExploitabilityText(finding.llm_exploitability, verificationStatus)} 
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
                          {expandedFindingId === finding.id && (
                            <div className="p-6 bg-gray-800/30 border-t border-gray-700">
                              <div className="grid grid-cols-1 gap-6">
                                {/* Vulnerable Code Section */}
                                <div className="bg-gray-800/50 rounded-lg p-4 border border-gray-700">
                                  <div className="flex items-center justify-between mb-3">
                                    <h4 className="text-lg font-medium text-gray-200">Vulnerable Code</h4>
                                    {isDependencyCheckFinding(finding) && finding.affected_files && (
                                      <div className="font-mono text-sm text-gray-400">
                                        {finding.affected_files.join(', ')}
                                      </div>
                                    )}
                                  </div>
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
                                        id={`${finding.id}-description-content`}
                                        className="text-gray-300"
                                      >
                                        {getDescription(finding)}
                                      </div>
                                    </div>
                                  </div>
                                  
                                  <div className="bg-gray-800/50 rounded-lg p-4 border border-gray-700">
                                    <div className="flex items-center gap-2 mb-2">
                                      <h4 className="text-lg font-medium text-gray-200">Exploitability</h4>
                                      {/* Pass verificationStatus here too */}
                                      <span className={`px-3 py-1 rounded-full text-sm font-medium ${getExploitabilityColor(finding.llm_exploitability, verificationStatus)}`}> 
                                        {getExploitabilityText(finding.llm_exploitability, verificationStatus)} 
                                      </span>
                                    </div>
                                    <div className="relative">
                                      <div 
                                        id={`${finding.id}-exploitability-content`}
                                        className="text-gray-300 whitespace-pre-wrap"
                                      >
                                        {finding.analysis?.impact || "No impact information available"}
                                      </div>
                                    </div>
                                  </div>
                                </div>

                                {/* Data Flow Section */}
                                <div className="bg-gray-800/50 rounded-lg p-4 border border-gray-700">
                                  <h4 className="text-lg font-medium text-gray-200 mb-3">Data Flow</h4>
                                  <div className="relative">
                                    <div 
                                      id={`${finding.id}-dataflow-content`}
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
                                        id={`${finding.id}-recommendations-content`}
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
                      );
                    })}
                  </div>
                  {/* Pagination Controls - CodeQL */} 
                  {totalCodeQLPages > 1 && (
                    <div className="flex items-center justify-between p-4 bg-gray-800/50 border-t border-gray-700">
                      <div className="flex gap-2">
                        <button 
                          onClick={() => setCodeQLCurrentPage(1)} // Go to first page
                          disabled={codeQLCurrentPage === 1}
                          className="px-4 py-2 text-sm font-medium text-white bg-gray-600 rounded-md hover:bg-gray-700 disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
                        >
                          First
                        </button>
                        <button 
                          onClick={handleCodeQLPrev}
                          disabled={codeQLCurrentPage === 1}
                          className="px-4 py-2 text-sm font-medium text-white bg-blue-600 rounded-md hover:bg-blue-700 disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
                        >
                          Previous
                        </button>
                      </div>
                      <span className="text-sm text-gray-400">
                        Page {codeQLCurrentPage} of {totalCodeQLPages}
                      </span>
                      <div className="flex gap-2">
                        <button 
                          onClick={handleCodeQLNext}
                          disabled={codeQLCurrentPage === totalCodeQLPages}
                          className="px-4 py-2 text-sm font-medium text-white bg-blue-600 rounded-md hover:bg-blue-700 disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
                        >
                          Next
                        </button>
                        <button 
                          onClick={() => setCodeQLCurrentPage(totalCodeQLPages)} // Go to last page
                          disabled={codeQLCurrentPage === totalCodeQLPages}
                          className="px-4 py-2 text-sm font-medium text-white bg-gray-600 rounded-md hover:bg-gray-700 disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
                        >
                          Last
                        </button>
                      </div>
                    </div>
                  )}
                </div>
              </>
            )}

            {(activeTab as string) === 'dependency' && (
              <>
                {/* Stats Charts */}
                <div className="grid grid-cols-1 lg:grid-cols-3 gap-6 mb-8">
                  <BarChart 
                    data={severityStats} 
                    title="Severity" 
                  />
                  <BarChart 
                    // Pass dependency findings to calculateExploitabilityStats
                    data={calculateExploitabilityStats(sortedDependencyFindings as unknown as CodeQLFinding[] || [])} 
                    title="Exploitability" 
                  />
                  <BarChart 
                    data={calculatePriorityStats(sortedDependencyFindings as unknown as CodeQLFinding[])} 
                    title="Priority Level" 
                  />
                </div>
              
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
                    {paginatedDependencyFindings.map((finding) => { // Use braces for block scope
                      // For dependencies, pass default 'True Positive' as verification status
                      const defaultVerification = 'True Positive';
                      return (
                        <div key={finding.id}>
                          {/* Row */}
                          <div 
                            className="grid grid-cols-12 text-sm hover:bg-gray-800/50 cursor-pointer transition-colors"
                            onClick={() => handleFindingClick(finding.id)}
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
                          {expandedFindingId === finding.id && (
                            <div className="p-6 bg-gray-800/30 border-t border-gray-700">
                              <div className="grid grid-cols-1 gap-6">
                                {/* Vulnerable Code Section */}
                                <div className="bg-gray-800/50 rounded-lg p-4 border border-gray-700">
                                  <div className="flex items-center justify-between mb-3">
                                    <h4 className="text-lg font-medium text-gray-200">Vulnerable Code</h4>
                                    {isDependencyCheckFinding(finding) && finding.affected_files && (
                                      <div className="font-mono text-sm text-gray-400">
                                        {finding.affected_files.join(', ')}
                                      </div>
                                    )}
                                  </div>
                                  <pre className="bg-black p-4 rounded-lg overflow-x-auto">
                                    <code className="text-sm font-mono text-gray-300">
                                      {finding.code_context || finding.analysis?.vulnerableCode || "No code context available"}
                                    </code>
                                  </pre>
                                </div>

                                {/* Analysis Grid */}
                                <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
                                  <div className="bg-gray-800/50 rounded-lg p-4 border border-gray-700">
                                    <h4 className="text-lg font-medium text-gray-200 mb-2">Description</h4>
                                    <div className="relative">
                                      <div 
                                        id={`${finding.id}-description-content`}
                                        className="text-gray-300"
                                      >
                                        {getDescription(finding)}
                                      </div>
                                    </div>
                                  </div>
                                  
                                  <div className="bg-gray-800/50 rounded-lg p-4 border border-gray-700">
                                    <div className="flex items-center gap-2 mb-2">
                                      <h4 className="text-lg font-medium text-gray-200">Exploitability</h4>
                                      {/* Corrected: Pass defaultVerification constant directly */}
                                      <span className={`px-3 py-1 rounded-full text-sm font-medium ${getExploitabilityColor(finding.llm_exploitability, defaultVerification)}`}>
                                        {getExploitabilityText(finding.llm_exploitability, defaultVerification)}
                                      </span>
                                    </div>
                                    <div className="relative">
                                      <div 
                                        id={`${finding.id}-exploitability-content`}
                                        className="text-gray-300 whitespace-pre-wrap"
                                      >
                                        {finding.analysis?.impact || "No impact information available"}
                                      </div>
                                    </div>
                                  </div>
                                </div>

                                {/* Data Flow Section */}
                                <div className="bg-gray-800/50 rounded-lg p-4 border border-gray-700">
                                  <h4 className="text-lg font-medium text-gray-200 mb-3">Data Flow</h4>
                                  <div className="relative">
                                    <div 
                                      id={`${finding.id}-dataflow-content`}
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
                                        id={`${finding.id}-recommendations-content`}
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
                      )
                    })}
                  </div>
                  {/* Pagination Controls - Dependency */}
                  {totalDependencyPages > 1 && (
                    <div className="flex items-center justify-between p-4 bg-gray-800/50 border-t border-gray-700">
                      <div className="flex gap-2">
                        <button 
                          onClick={() => setDependencyCurrentPage(1)} // Go to first page
                          disabled={dependencyCurrentPage === 1}
                          className="px-4 py-2 text-sm font-medium text-white bg-gray-600 rounded-md hover:bg-gray-700 disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
                        >
                          First
                        </button>
                        <button 
                          onClick={handleDependencyPrev}
                          disabled={dependencyCurrentPage === 1}
                          className="px-4 py-2 text-sm font-medium text-white bg-blue-600 rounded-md hover:bg-blue-700 disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
                        >
                          Previous
                        </button>
                      </div>
                      <span className="text-sm text-gray-400">
                        Page {dependencyCurrentPage} of {totalDependencyPages}
                      </span>
                      <div className="flex gap-2">
                        <button 
                          onClick={handleDependencyNext}
                          disabled={dependencyCurrentPage === totalDependencyPages}
                          className="px-4 py-2 text-sm font-medium text-white bg-blue-600 rounded-md hover:bg-blue-700 disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
                        >
                          Next
                        </button>
                        <button 
                          onClick={() => setDependencyCurrentPage(totalDependencyPages)} // Go to last page
                          disabled={dependencyCurrentPage === totalDependencyPages}
                          className="px-4 py-2 text-sm font-medium text-white bg-gray-600 rounded-md hover:bg-gray-700 disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
                        >
                          Last
                        </button>
                      </div>
                    </div>
                  )}
                </div>
              </>
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
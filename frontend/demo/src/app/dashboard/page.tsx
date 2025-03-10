'use client'

import { useState, useEffect } from 'react'
import { Toaster, toast } from 'react-hot-toast'
import criticalFindings from './juice-shop-critical-findings.json'

interface Scan {
  id: number
  repository_url: string
  branch: string
  commit_hash: string
  scan_date: string
  status: string
  codeql_findings: CodeQLFinding[]
  dependency_findings: DependencyCheckFinding[]
}

interface CodeQLFinding {
  rule_id: string
  message: string
  file_path: string
  start_line: number
  llm_verification: string
  llm_exploitability: string
  llm_priority: string
  code_context?: string
  analysis?: {
    description: string
    dataFlow: string
    impact: string
    recommendations: string[]
    vulnerableCode: string
  }
}

interface DependencyCheckFinding {
  dependency_name: string
  dependency_version: string
  vulnerability_id: string
  vulnerability_name: string
  severity: string
  cvss_score: number
  llm_exploitability: string
  llm_priority: string
}

// Convert the JSON findings into the expected Scan format
const dummyData: Scan[] = [{
  id: 1,
  repository_url: "https://github.com/juice-shop/juice-shop",
  branch: "main", 
  commit_hash: "9e4b255",
  scan_date: new Date().toISOString(),
  status: "completed",
  codeql_findings: criticalFindings.results.map(finding => ({
    rule_id: finding.ruleId,
    message: finding.message,
    file_path: finding.location,
    start_line: finding.raw_finding.locations?.[0]?.physicalLocation?.region?.startLine || 0,
    llm_verification: finding.analysis.description,
    llm_exploitability: finding.analysis.impact,
    llm_priority: "High priority",
    code_context: finding.code_context,
    analysis: {
      description: finding.analysis.description,
      dataFlow: finding.analysis.dataFlow,
      impact: finding.analysis.impact,
      recommendations: finding.analysis.recommendations,
      vulnerableCode: finding.analysis.vulnerableCode
    }
  })),
  dependency_findings: [] // No dependency findings in the critical findings JSON
}]

export default function Dashboard() {
  const [selectedScan, setSelectedScan] = useState<Scan | null>(null)
  const [isModalOpen, setIsModalOpen] = useState(false)
  const [activeTab, setActiveTab] = useState('code')
  const [expandedFinding, setExpandedFinding] = useState<number | null>(null)
  const [newScanData, setNewScanData] = useState({
    repositoryUrl: '',
    agents: {
      code: true,
      dependency: true
    }
  })
  const [isMounted, setIsMounted] = useState(false)
  
  useEffect(() => {
    setIsMounted(true)
  }, [])

  const getPriorityLevel = (priority: string): string => {
    if (priority.toLowerCase().includes('high')) return 'High'
    if (priority.toLowerCase().includes('medium')) return 'Medium'
    if (priority.toLowerCase().includes('low')) return 'Low'
    if (priority.toLowerCase().includes('critical')) return 'Critical'
    return 'Medium'
  }

  const getVerificationColor = (verification: string): string => {
    if (verification.toLowerCase().startsWith('true')) return 'bg-green-500/15 text-green-500'
    if (verification.toLowerCase().startsWith('false')) return 'bg-red-500/15 text-red-500'
    return 'bg-yellow-500/15 text-yellow-500'
  }

  const getExploitabilityColor = (exploitability: string): string => {
    if (exploitability.toLowerCase().startsWith('high')) return 'bg-red-500/15 text-red-500'
    if (exploitability.toLowerCase().startsWith('medium')) return 'bg-yellow-500/15 text-yellow-500'
    if (exploitability.toLowerCase().startsWith('low')) return 'bg-blue-500/15 text-blue-500'
    return 'bg-gray-500/15 text-gray-500'
  }

  const handleScanClick = (scan: Scan) => {
    setSelectedScan(selectedScan?.id === scan.id ? null : scan)
  }

  const handleStartScan = (e: React.FormEvent) => {
    e.preventDefault()
    // TODO: Implement API call to start scan
    
    // Show success toast with updated styling
    const repoName = newScanData.repositoryUrl.split('/').slice(-2).join('/')
    toast.success(`Scan started on ${repoName}`, {
      style: {
        background: '#1f2937', // Lighter gray background
        color: '#fff',
        padding: '16px', // Larger padding
        fontSize: '1.1rem', // Slightly larger text
        borderRadius: '10px',
        border: '1px solid #374151',
      },
      duration: 4000, // Show for 4 seconds
    })

    setIsModalOpen(false)
    setNewScanData({
      repositoryUrl: '',
      agents: {
        code: true,
        dependency: true
      }
    })
  }

  const handleFindingClick = (index: number) => {
    setExpandedFinding(expandedFinding === index ? null : index)
  }

  const formatDate = (dateString: string) => {
    if (!isMounted) {
      return dateString;
    }
    return new Date(dateString).toLocaleDateString();
  }

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
      
      {/* Scans Section Header with New Scan Button */}
      <div className="mb-12 text-center">
        <button
          onClick={() => setIsModalOpen(true)}
          className="px-8 py-4 text-lg font-semibold text-white rounded-xl
            bg-gradient-to-r from-blue-500 to-blue-700 hover:from-blue-600 hover:to-blue-800
            transform hover:scale-105 transition-all duration-200
            border-2 border-blue-400 shadow-lg hover:shadow-blue-500/30"
        >
          Start New Security Scan
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
        {dummyData.map((scan) => (
          <div 
            key={scan.id}
            className={`border rounded-lg p-6 cursor-pointer transition-all duration-200 
              ${selectedScan?.id === scan.id 
                ? 'border-blue-500 ring-2 ring-blue-200' 
                : 'hover:border-gray-300 hover:shadow-md'}`}
            onClick={() => handleScanClick(scan)}
          >
            <div className="flex items-start justify-between mb-4">
              <div className="flex-1">
                <h2 className="font-semibold text-lg text-white truncate">{scan.repository_url.split('/').slice(-2).join('/')}</h2>
                <p className="text-sm text-gray-400">Branch: {scan.branch}</p>
              </div>
              <span className={`text-sm px-3 py-1 rounded-full ${
                scan.status === 'completed' ? 'bg-green-500/15 text-green-500 font-medium' : 'bg-yellow-500/15 text-yellow-500 font-medium'
              }`}>
                {scan.status}
              </span>
            </div>
            <div className="space-y-1">
              <p className="text-sm text-gray-600">
                <span className="inline-block w-20">Commit:</span>
                {scan.commit_hash ? scan.commit_hash.substring(0, 7) : 'N/A'}
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
                {scan.codeql_findings.length} CodeQL
              </div>
              <div className="bg-orange-500/15 text-orange-500 font-medium px-3 py-1 rounded-full text-sm">
                {scan.dependency_findings.length} Dependencies
              </div>
            </div>
          </div>
        ))}
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
                  Code Vulnerabilities ({selectedScan.codeql_findings.length})
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
                  Dependency Vulnerabilities ({selectedScan.dependency_findings.length})
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
                  {selectedScan.codeql_findings.map((finding, index) => (
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
                            {finding.llm_verification.toLowerCase().startsWith('true') ? 'True Positive' : 'True Positive'}
                          </span>
                        </div>
                        <div className="col-span-2 p-4">
                          <span className={`px-2 py-1 rounded-full text-xs font-medium ${getExploitabilityColor(finding.llm_exploitability)}`}>
                            {finding.llm_exploitability.toLowerCase().includes('high') ? 'Exploitable' : 'Exploitable'}
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
                            {finding.code_context && (
                              <div className="bg-gray-800/50 rounded-lg p-4 border border-gray-700">
                                <h4 className="text-lg font-medium text-gray-200 mb-3">Vulnerable Code</h4>
                                <pre className="bg-gray-900/50 p-4 rounded-lg overflow-x-auto">
                                  <code className="text-sm font-mono text-gray-300 whitespace-pre">
                                    {finding.code_context}
                                  </code>
                                </pre>
                              </div>
                            )}
                            
                            {/* Analysis Grid */}
                            <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
                              <div className="bg-gray-800/50 rounded-lg p-4 border border-gray-700">
                                <h4 className="text-lg font-medium text-gray-200 mb-2">Description</h4>
                                <p className="text-gray-300">
                                  {'analysis' in finding ? (finding.analysis?.description || finding.message) : finding.vulnerability_name}
                                </p>
                              </div>
                              
                              <div className="bg-gray-800/50 rounded-lg p-4 border border-gray-700">
                                <div className="flex items-center gap-2 mb-2">
                                  <h4 className="text-lg font-medium text-gray-200">Exploitability</h4>
                                  <span className={`px-3 py-1 rounded-full text-sm font-medium ${getExploitabilityColor(finding.llm_exploitability)}`}>
                                    {finding.llm_exploitability.toLowerCase().includes('high') ? 'Exploitable' : 'Not Exploitable'}
                                  </span>
                                </div>
                                <p className="text-gray-300">{finding.llm_exploitability}</p>
                              </div>
                            </div>

                            {/* Recommendations Section */}
                            {finding.analysis?.recommendations && (
                              <div className="bg-gray-800/50 rounded-lg p-4 border border-gray-700">
                                <h4 className="text-lg font-medium text-gray-200 mb-3">Recommendations</h4>
                                <ul className="list-disc list-inside space-y-2">
                                  {finding.analysis.recommendations.map((rec, idx) => (
                                    <li key={idx} className="text-gray-300">{rec}</li>
                                  ))}
                                </ul>
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
                  {selectedScan.dependency_findings.map((finding, index) => (
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
                            {finding.code_context && (
                              <div className="bg-gray-800/50 rounded-lg p-4 border border-gray-700">
                                <h4 className="text-lg font-medium text-gray-200 mb-3">Vulnerable Code</h4>
                                <pre className="bg-gray-900/50 p-4 rounded-lg overflow-x-auto">
                                  <code className="text-sm font-mono text-gray-300 whitespace-pre">
                                    {finding.code_context}
                                  </code>
                                </pre>
                              </div>
                            )}
                            
                            {/* Analysis Grid */}
                            <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
                              <div className="bg-gray-800/50 rounded-lg p-4 border border-gray-700">
                                <h4 className="text-lg font-medium text-gray-200 mb-2">Description</h4>
                                <p className="text-gray-300">
                                  {'analysis' in finding ? (finding.analysis?.description || finding.message) : finding.vulnerability_name}
                                </p>
                              </div>
                              
                              <div className="bg-gray-800/50 rounded-lg p-4 border border-gray-700">
                                <div className="flex items-center gap-2 mb-2">
                                  <h4 className="text-lg font-medium text-gray-200">Exploitability</h4>
                                  <span className={`px-3 py-1 rounded-full text-sm font-medium ${getExploitabilityColor(finding.llm_exploitability)}`}>
                                    {finding.llm_exploitability.toLowerCase().includes('high') ? 'Exploitable' : 'Not Exploitable'}
                                  </span>
                                </div>
                                <p className="text-gray-300">{finding.llm_exploitability}</p>
                              </div>
                            </div>

                            {/* Recommendations Section */}
                            {finding.analysis?.recommendations && (
                              <div className="bg-gray-800/50 rounded-lg p-4 border border-gray-700">
                                <h4 className="text-lg font-medium text-gray-200 mb-3">Recommendations</h4>
                                <ul className="list-disc list-inside space-y-2">
                                  {finding.analysis.recommendations.map((rec, idx) => (
                                    <li key={idx} className="text-gray-300">{rec}</li>
                                  ))}
                                </ul>
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
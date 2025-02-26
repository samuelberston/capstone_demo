'use client'

import { useState } from 'react'

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

// Dummy data based on seed.py
const dummyData: Scan[] = [
  {
    id: 1,
    repository_url: "https://github.com/juice-shop/juice-shop",
    branch: "main",
    commit_hash: "9e4b255",
    scan_date: new Date(Date.now() - 86400000).toISOString(),
    status: "completed",
    codeql_findings: [
      {
        rule_id: "js/sql-injection",
        message: "Possible SQL injection vulnerability in query construction",
        file_path: "src/controllers/user.js",
        start_line: 45,
        llm_verification: "The finding appears to be a true positive. The code directly concatenates user input into SQL queries.",
        llm_exploitability: "High - The vulnerability is easily exploitable using simple SQL injection payloads.",
        llm_priority: "High priority - Should be fixed immediately due to high exploitability and potential impact."
      },
      {
        rule_id: "js/xss",
        message: "Cross-site scripting vulnerability due to unescaped output",
        file_path: "src/views/profile.js",
        start_line: 23,
        llm_verification: "Confirmed true positive. User input is rendered directly to HTML without sanitization.",
        llm_exploitability: "Medium - Requires user interaction but could lead to session hijacking.",
        llm_priority: "Medium priority - Should be addressed in the next sprint."
      }
    ],
    dependency_findings: [
      {
        dependency_name: "express-jwt",
        dependency_version: "0.1.3",
        vulnerability_id: "CVE-2020-15084",
        vulnerability_name: "Authorization Bypass",
        severity: "CRITICAL",
        cvss_score: 9.1,
        llm_exploitability: "High - The vulnerability allows bypassing authentication when specific conditions are met.",
        llm_priority: "Critical priority - This vulnerability could lead to unauthorized access and should be patched immediately."
      },
      {
        dependency_name: "nanoid",
        dependency_version: "3.1.20",
        vulnerability_id: "CVE-2021-23566",
        vulnerability_name: "Information Exposure",
        severity: "MEDIUM",
        cvss_score: 5.5,
        llm_exploitability: "Medium - An attacker could potentially predict or reproduce generated IDs, leading to information disclosure.",
        llm_priority: "Medium priority - While not critical, this should be addressed to prevent potential ID prediction attacks."
      }
    ]
  },
  // Add the second scan from your seed data here
]

export default function Dashboard() {
  const [selectedScan, setSelectedScan] = useState<Scan | null>(null)
  const [isModalOpen, setIsModalOpen] = useState(false)
  const [newScanData, setNewScanData] = useState({
    repositoryUrl: '',
    agents: {
      code: true,
      dependency: true
    }
  })

  const getPriorityLevel = (priority: string): string => {
    if (priority.toLowerCase().includes('high')) return 'HIGH'
    if (priority.toLowerCase().includes('medium')) return 'MEDIUM'
    if (priority.toLowerCase().includes('low')) return 'LOW'
    if (priority.toLowerCase().includes('critical')) return 'CRITICAL'
    return 'MEDIUM'
  }

  const getSeverityColor = (severity: string) => {
    switch (severity.toUpperCase()) {
      case 'CRITICAL': return 'bg-red-100 text-red-800'
      case 'HIGH': return 'bg-red-100 text-red-800'
      case 'MEDIUM': return 'bg-yellow-100 text-yellow-800'
      case 'LOW': return 'bg-blue-100 text-blue-800'
      default: return 'bg-gray-100 text-gray-800'
    }
  }

  const handleScanClick = (scan: Scan) => {
    setSelectedScan(selectedScan?.id === scan.id ? null : scan)
  }

  const handleStartScan = (e: React.FormEvent) => {
    e.preventDefault()
    // TODO: Implement API call to start scan
    console.log('Starting scan with:', newScanData)
    setIsModalOpen(false)
    setNewScanData({
      repositoryUrl: '',
      agents: {
        code: true,
        dependency: true
      }
    })
  }

  return (
    <div className="p-6 max-w-7xl mx-auto">
      <h1 className="text-3xl font-bold mb-8 text-white text-center">Security Scan Dashboard</h1>
      
      {/* Scans Section Header with New Scan Button */}
      <div className="mb-4 flex justify-between items-center">
        <h2 className="text-2xl font-semibold text-white">Recent Scans</h2>
        <button
          onClick={() => setIsModalOpen(true)}
          className="bg-blue-500 hover:bg-blue-600 text-white px-4 py-2 rounded-lg transition-colors"
        >
          Start New Scan
        </button>
      </div>

      {/* New Scan Modal */}
      {isModalOpen && (
        <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50">
          <div className="bg-gray-800 rounded-lg p-6 w-full max-w-md">
            <h3 className="text-xl font-semibold text-white mb-4">Start New Security Scan</h3>
            <form onSubmit={handleStartScan}>
              <div className="mb-4">
                <label htmlFor="repositoryUrl" className="block text-sm font-medium text-gray-300 mb-2">
                  GitHub Repository URL
                </label>
                <input
                  type="text"
                  id="repositoryUrl"
                  value={newScanData.repositoryUrl}
                  onChange={(e) => setNewScanData({...newScanData, repositoryUrl: e.target.value})}
                  placeholder="https://github.com/username/repository"
                  className="w-full p-2 rounded-md bg-gray-700 text-white border border-gray-600 focus:border-blue-500 focus:ring-1 focus:ring-blue-500"
                  required
                />
              </div>
              
              <div className="mb-6">
                <label className="block text-sm font-medium text-gray-300 mb-2">
                  Select Agents
                </label>
                <div className="space-y-2">
                  <label className="flex items-center space-x-2">
                    <input
                      type="checkbox"
                      checked={newScanData.agents.code}
                      onChange={(e) => setNewScanData({
                        ...newScanData,
                        agents: {...newScanData.agents, code: e.target.checked}
                      })}
                      className="rounded border-gray-600 text-blue-500 focus:ring-blue-500"
                    />
                    <span className="text-white">Code Analysis (CodeQL)</span>
                  </label>
                  <label className="flex items-center space-x-2">
                    <input
                      type="checkbox"
                      checked={newScanData.agents.dependency}
                      onChange={(e) => setNewScanData({
                        ...newScanData,
                        agents: {...newScanData.agents, dependency: e.target.checked}
                      })}
                      className="rounded border-gray-600 text-blue-500 focus:ring-blue-500"
                    />
                    <span className="text-white">Dependency Check</span>
                  </label>
                </div>
              </div>

              <div className="flex justify-end space-x-3">
                <button
                  type="button"
                  onClick={() => setIsModalOpen(false)}
                  className="px-4 py-2 text-gray-300 hover:text-white transition-colors"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  className="bg-blue-500 hover:bg-blue-600 text-white px-4 py-2 rounded-lg transition-colors"
                >
                  Start Scan
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

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
                scan.status === 'completed' ? 'bg-green-100 text-green-800' : 'bg-yellow-100 text-yellow-800'
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
                {new Date(scan.scan_date).toLocaleDateString()}
              </p>
            </div>
            <div className="mt-4 flex gap-3">
              <div className="bg-red-50 text-red-700 px-3 py-1 rounded-full text-sm">
                {scan.codeql_findings.length} CodeQL
              </div>
              <div className="bg-orange-50 text-orange-700 px-3 py-1 rounded-full text-sm">
                {scan.dependency_findings.length} Dependencies
              </div>
            </div>
          </div>
        ))}
      </div>

      {/* Selected Scan Details */}
      {selectedScan && (
        <div className="space-y-8">
          <div>
            <h2 className="text-2xl font-semibold mb-6 text-white">CodeQL Findings</h2>
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
              {selectedScan.codeql_findings.map((finding, index) => (
                <div key={index} className="border rounded-lg p-6 hover:shadow-md transition-shadow">
                  <div className="flex items-start justify-between">
                    <div className="flex-1">
                      <h3 className="font-semibold text-lg text-white">{finding.rule_id}</h3>
                      <p className="text-gray-300 mt-2">{finding.message}</p>
                    </div>
                    <span className={`px-3 py-1 rounded-full text-sm ${getSeverityColor(getPriorityLevel(finding.llm_priority))}`}>
                      {getPriorityLevel(finding.llm_priority)}
                    </span>
                  </div>
                  <div className="mt-4">
                    <div className="bg-gray-50 rounded-md p-3">
                      <h4 className="text-lg font-medium text-gray-700 mb-2">Location</h4>
                      <p className="text-sm font-mono text-gray-600">
                        {finding.file_path}:{finding.start_line}
                      </p>
                    </div>
                  </div>
                  <div className="mt-4 space-y-3">
                    <div className="bg-gray-50 rounded-md p-3">
                      <h4 className="text-lg font-medium text-gray-700 mb-2">Verification</h4>
                      <p className="text-gray-600">{finding.llm_verification}</p>
                    </div>
                    <div className="bg-gray-50 rounded-md p-3">
                      <h4 className="text-lg font-medium text-gray-700 mb-2">Exploitability</h4>
                      <p className="text-gray-600">{finding.llm_exploitability}</p>
                    </div>
                    <div className="bg-gray-50 rounded-md p-3">
                      <h4 className="text-lg font-medium text-gray-700 mb-2">Priority</h4>
                      <p className="text-gray-600">{finding.llm_priority}</p>
                    </div>
                  </div>
                </div>
              ))}
            </div>
          </div>

          <div>
            <h2 className="text-2xl font-semibold mb-6 text-white">Dependency Findings</h2>
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
              {selectedScan.dependency_findings.map((finding, index) => (
                <div key={index} className="border rounded-lg p-6 hover:shadow-md transition-shadow">
                  <div className="flex items-start justify-between">
                    <h3 className="font-semibold text-lg text-white">{finding.vulnerability_name}</h3>
                    <span className={`px-3 py-1 rounded-full text-sm ${getSeverityColor(finding.severity)}`}>
                      {finding.severity}
                    </span>
                  </div>
                  <div className="mt-4">
                    <div className="bg-gray-50 rounded-md p-3">
                      <h4 className="text-lg font-medium text-gray-700 mb-2">Dependency Details</h4>
                      <p className="text-sm font-mono text-gray-600">
                        {finding.dependency_name}@{finding.dependency_version}
                      </p>
                      <p className="text-gray-600 mt-2">{finding.vulnerability_id}</p>
                      <div className="flex items-center gap-2 mt-2">
                        <span className="text-gray-600">CVSS Score:</span>
                        <span className={`px-2 py-1 rounded text-sm ${getSeverityColor(finding.severity)}`}>
                          {finding.cvss_score}
                        </span>
                      </div>
                    </div>
                  </div>
                  <div className="mt-4 space-y-3">
                    <div className="bg-gray-50 rounded-md p-3">
                      <h4 className="text-lg font-medium text-gray-700 mb-2">Exploitability</h4>
                      <p className="text-gray-600">{finding.llm_exploitability}</p>
                    </div>
                    <div className="bg-gray-50 rounded-md p-3">
                      <h4 className="text-lg font-medium text-gray-700 mb-2">Priority</h4>
                      <p className="text-gray-600">{finding.llm_priority}</p>
                    </div>
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
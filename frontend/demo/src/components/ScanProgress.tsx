import { Scan } from '@/types/scan';
import { formatDistanceToNow } from 'date-fns';

interface ScanProgressProps {
  scan: Scan;
}

export function ScanProgress({ scan }: ScanProgressProps) {
  if (!scan.progress_details) {
    return (
      <div className="mb-4">
        <div className="flex justify-between text-sm text-gray-400 mb-1">
          <span>{scan.current_step?.replace(/_/g, ' ').replace(/\b\w/g, l => l.toUpperCase())}</span>
          <span>{scan.progress_percentage}%</span>
        </div>
        <div className="w-full bg-gray-700 rounded-full h-2">
          <div 
            className="bg-blue-500 h-2 rounded-full transition-all duration-500"
            style={{ width: `${scan.progress_percentage || 0}%` }}
          ></div>
        </div>
        {scan.status_message && (
          <p className="text-sm text-gray-400 mt-2">{scan.status_message}</p>
        )}
      </div>
    );
  }

  const details = scan.progress_details;
  const currentStep = details.step_history.find(step => step.status === 'running');

  return (
    <div className="space-y-4">
      {/* Overall Progress */}
      <div className="flex justify-between text-sm text-gray-400 mb-1">
        <span>Overall Progress</span>
        <span>{Math.round((details.step_progress / details.total_steps) * 100)}%</span>
      </div>
      <div className="w-full bg-gray-700 rounded-full h-2">
        <div 
          className="bg-blue-500 h-2 rounded-full transition-all duration-500"
          style={{ width: `${(details.step_progress / details.total_steps) * 100}%` }}
        ></div>
      </div>

      {/* Current Step */}
      <div className="bg-gray-800/50 rounded-lg p-4 border border-gray-700">
        <div className="flex justify-between items-center mb-2">
          <h4 className="text-sm font-medium text-gray-200">Current Step</h4>
          <span className="text-sm text-blue-400">{currentStep?.step}</span>
        </div>
        
        {/* Step Progress */}
        {details.current_step_details.total_dependencies && (
          <div className="space-y-2">
            <div className="flex justify-between text-sm text-gray-400">
              <span>Dependencies Analyzed</span>
              <span>
                {details.current_step_details.dependencies_analyzed} / {details.current_step_details.total_dependencies}
              </span>
            </div>
            <div className="w-full bg-gray-700 rounded-full h-1">
              <div 
                className="bg-blue-500 h-1 rounded-full transition-all duration-500"
                style={{ 
                  width: `${(details.current_step_details.dependencies_analyzed || 0) / details.current_step_details.total_dependencies * 100}%` 
                }}
              ></div>
            </div>
          </div>
        )}

        {/* Vulnerabilities Found */}
        {details.current_step_details.vulnerabilities_found !== undefined && (
          <div className="mt-2 text-sm text-gray-400">
            <span>Vulnerabilities Found: </span>
            <span className="text-red-400">{details.current_step_details.vulnerabilities_found}</span>
          </div>
        )}

        {/* Estimated Time */}
        {details.current_step_details.estimated_time_remaining && (
          <div className="mt-2 text-sm text-gray-400">
            <span>Estimated Time Remaining: </span>
            <span className="text-blue-400">{details.current_step_details.estimated_time_remaining}</span>
          </div>
        )}
      </div>

      {/* Step History */}
      <div className="bg-gray-800/50 rounded-lg p-4 border border-gray-700">
        <h4 className="text-sm font-medium text-gray-200 mb-2">Step History</h4>
        <div className="space-y-2">
          {details.step_history.map((step, index) => (
            <div key={index} className="flex items-center justify-between text-sm">
              <span className={`${
                step.status === 'completed' ? 'text-green-400' :
                step.status === 'running' ? 'text-blue-400' :
                'text-red-400'
              }`}>
                {step.step}
              </span>
              <span className="text-gray-400">
                {step.status === 'running' ? 'Running' : 
                 formatDistanceToNow(new Date(step.end_time || step.start_time), { addSuffix: true })}
              </span>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
} 
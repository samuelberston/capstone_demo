import { Scan } from '@/types/scan';
import { formatDistanceToNow } from 'date-fns';

interface ScanProgressProps {
  scan: Scan;
}

export function ScanProgress({ scan }: ScanProgressProps) {
  // Calculate overall progress based on CodeQL and Dependency status
  const getOverallProgress = () => {
    const codeqlProgress = scan.codeql_status === 'completed' ? 100 : 
                          scan.codeql_status === 'running' ? 50 : 0;
    const depProgress = scan.dependency_status === 'completed' ? 100 : 
                       scan.dependency_status === 'running' ? 50 : 0;
    
    return Math.round((codeqlProgress + depProgress) / 2);
  };

  return (
    <div className="mb-4">
      <div className="flex justify-between text-sm text-gray-400 mb-1">
        <span>{scan.current_step?.replace(/_/g, ' ').replace(/\b\w/g, l => l.toUpperCase())}</span>
        <span>{scan.progress_percentage || getOverallProgress()}%</span>
      </div>
      <div className="w-full bg-gray-700 rounded-full h-2">
        <div 
          className="bg-blue-500 h-2 rounded-full transition-all duration-500"
          style={{ width: `${scan.progress_percentage || getOverallProgress()}%` }}
        ></div>
      </div>
      {scan.status_message && (
        <div className="mt-2">
          <p className="text-sm text-gray-400">{scan.status_message}</p>
          {scan.codeql_status === 'running' && (
            <p className="text-sm text-blue-400">CodeQL Analysis in progress...</p>
          )}
          {scan.dependency_status === 'running' && (
            <p className="text-sm text-blue-400">Dependency Check in progress...</p>
          )}
        </div>
      )}
    </div>
  );
} 
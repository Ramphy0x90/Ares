export interface Scan {
  id: number;
  target_id: number;
  scan_config_id: number | null;
  status: 'pending' | 'running' | 'completed' | 'failed' | 'cancelled';
  progress: number;
  started_at: string | null;
  completed_at: string | null;
  error_message: string | null;
  created_at: string;
}

export interface ScanCreate {
  target_id: number;
  scan_config_id?: number;
  scanners?: string[];
  options?: Record<string, unknown>;
}

export interface ScanConfig {
  id: number;
  name: string;
  scanners: string;
  options: string | null;
  created_at: string;
}

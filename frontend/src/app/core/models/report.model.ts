export interface Report {
  id: number;
  scan_id: number;
  title: string;
  format: 'html' | 'pdf' | 'json';
  file_path: string | null;
  created_at: string;
}

export interface ReportCreate {
  scan_id: number;
  title: string;
  format: string;
}

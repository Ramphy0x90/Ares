export interface Target {
  id: number;
  name: string;
  host: string;
  target_type: 'host' | 'url' | 'api' | 'llm_endpoint';
  description: string | null;
  tags: string | null;
  created_at: string;
  updated_at: string;
}

export interface TargetCreate {
  name: string;
  host: string;
  target_type: string;
  description?: string;
  tags?: string[];
}

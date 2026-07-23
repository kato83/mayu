export type IngestType =
  | 'ecosystem' | 'ecosystem_update'
  | 'all' | 'all_bulk'
  | 'nvd' | 'nvd_update' | 'nvd_converted'
  | 'mitre' | 'mitre_update'
  | 'epss' | 'epss_update' | 'epss_backfill'
  | 'kev' | 'kev_update'
  | 'debian'
  | 'ghsa';

export interface IngestParams {
  type: IngestType;
  ecosystem?: string;
  repo?: string;
  from?: string;
  to?: string;
}

export interface IngestEvent {
  phase: 'download' | 'parse' | 'store' | 'summary' | 'done' | 'error';
  current?: number;
  total?: number;
  message?: string;
}

export interface IngestStartResponse {
  job_id: number;
  status: string;
}

export interface IngestJob {
  id: number;
  source: string;
  command_args: Record<string, unknown>;
  started_at: string;
  finished_at: string | null;
  status: 'running' | 'success' | 'failed' | 'partial';
  total_count: number | null;
  success_count: number | null;
  failure_count: number | null;
  error_message: string | null;
  error_stack: string | null;
}

export interface IngestFailure {
  id: number;
  vuln_id: string;
  error_type: string;
  error_message: string | null;
  error_stack: string | null;
  failed_at: string;
}

export interface IngestJobDetail extends IngestJob {
  failures: IngestFailure[];
}

export interface IngestJobsResponse {
  jobs: IngestJob[];
}

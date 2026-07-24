export interface SyncState {
  source: string;
  source_type: string;
  last_modified_at: string;
  last_synced_at: string;
  record_count: number;
}

export interface EPSSCoverage {
  total_days: number;
  first_date: string;
  last_date: string;
  total_scores: number;
  missing_dates: string[];
}

export interface StatusResponse {
  sync_states: SyncState[];
  epss_coverage: EPSSCoverage | null;
}

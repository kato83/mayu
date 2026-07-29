export interface Watchlist {
  id: number;
  user_id: number;
  name: string;
  match_type: 'package' | 'purl' | 'cpe' | 'ecosystem';
  team_id?: number;
  ecosystem?: string;
  package_name?: string;
  purl_pattern?: string;
  cpe_pattern?: string;
  severity_min?: number;
  epss_threshold?: number;
  enabled: boolean;
  created_at: string;
  updated_at: string;
}

export interface WatchlistMatch {
  id: number;
  watchlist_id: number;
  vulnerability_id: string;
  matched_at: string;
  notified: boolean;
  notified_at?: string;
}

export interface CreateWatchlistRequest {
  name: string;
  match_type: 'package' | 'purl' | 'cpe' | 'ecosystem';
  team_id?: number;
  ecosystem?: string;
  package_name?: string;
  purl_pattern?: string;
  cpe_pattern?: string;
  severity_min?: number;
  epss_threshold?: number;
}

export interface UpdateWatchlistRequest {
  name: string;
  match_type: 'package' | 'purl' | 'cpe' | 'ecosystem';
  ecosystem?: string;
  package_name?: string;
  purl_pattern?: string;
  cpe_pattern?: string;
  severity_min?: number;
  epss_threshold?: number;
  enabled?: boolean;
}

export interface WatchlistMatchesResponse {
  matches: WatchlistMatch[];
  total: number;
}

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

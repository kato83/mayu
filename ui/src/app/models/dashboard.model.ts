export interface DashboardSummary {
  total_vulnerabilities: number;
  last_7_days: number;
  last_30_days: number;
  critical_count: number;
  high_count: number;
  in_kev_count: number;
}

export interface DashboardTrends {
  daily_new_vulns: TrendDataPoint[];
}

export interface TrendDataPoint {
  date: string;
  count: number;
}

export interface DashboardDistributions {
  severity: DistributionItem[];
  severity_best: DistributionItem[];
  ecosystems: DistributionItem[];
  epss_histogram: HistogramBucket[];
  lev_histogram: HistogramBucket[];
}

export interface DistributionItem {
  label: string;
  count: number;
}

export interface HistogramBucket {
  range_label: string;
  min: number;
  max: number;
  count: number;
}

export interface DashboardTopRisks {
  top_epss: RiskEntry[];
  top_lev: RiskEntry[];
}

export interface RiskEntry {
  vulnerability_id: string;
  summary: string;
  score: number;
  percentile?: number;
  severity?: string;
}

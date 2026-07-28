export interface StatsTrendResponse {
  range: string;
  group_by: string;
  data_points: StatsTrendDataPoint[];
}

export interface StatsTrendDataPoint {
  date: string;
  total: number;
  critical: number;
  high: number;
  medium: number;
  low: number;
  new?: number;
  resolved?: number;
}

/** Priority level determined by the triage engine */
export type PriorityLevel = 'Critical' | 'High' | 'Medium' | 'Low';

/** Individual signal contribution to the composite score */
export interface SignalContribution {
  name: string;
  raw_value: number;
  normalized_value: number;
  weight: number;
  effective_weight: number;
  contribution: number;
}

/** Result of triaging a single vulnerability */
export interface TriageResult {
  vulnerability_id: string;
  priority_level: PriorityLevel;
  composite_score: number;
  ssvc_decision: string;
  rationale: TriageRationale;
  signal_values: SignalContribution[];
  profile_used: string;
  computed_at: string;
}

/** Human-readable rationale for a triage decision */
export interface TriageRationale {
  summary: string;
  top_factors: TriageFactor[];
  signal_details: string[];
  ssvc_decision: string;
  resolution_method: string;
}

/** A factor contributing to the triage decision */
export interface TriageFactor {
  description: string;
  impact: number;
}

/** Summary counts by priority level for the dashboard */
export interface TriageSummary {
  critical: number;
  high: number;
  medium: number;
  low: number;
  total_triaged: number;
  profile_used: string;
  last_computed: string;
}

/** A triage profile definition */
export interface TriageProfile {
  name: string;
  description: string;
  base: string;
  weights: ExtendedWeights;
  thresholds: Thresholds;
}

/** Extended weights for the composite score calculation */
export interface ExtendedWeights {
  cvss: number;
  epss: number;
  lev: number;
  kev: number;
  patch: number;
  age: number;
  exploit_db: number;
  reachability: number;
}

/** Priority level thresholds */
export interface Thresholds {
  critical: number;
  high: number;
  medium: number;
}

/** Cross-project triage result */
export interface CrossProjectTriageResult {
  vulnerability_id: string;
  org_priority_level: PriorityLevel;
  max_composite_score: number;
  affected_servers: number;
  affected_projects: number;
  server_breakdown: ServerTriageEntry[];
}

/** A single server's triage entry for cross-project view */
export interface ServerTriageEntry {
  project_id: string;
  project_name: string;
  server_label: string;
  environment: string;
  profile_used: string;
  triage_result: TriageResult;
}

/** Cross-project overview summary */
export interface TriageOverviewSummary {
  total_vulnerabilities: number;
  priority_counts: Record<PriorityLevel, number>;
  total_projects: number;
  total_servers: number;
}

/** Triage Path: a grouped remediation action */
export interface TriagePath {
  id: string;
  action: RemediationAction;
  resolved_vulnerabilities: ResolvedVulnEntry[];
  affected_servers: string[];
  impact_score: number;
  max_priority_level: PriorityLevel;
  total_vuln_count: number;
  total_server_count: number;
}

/** A remediation action (e.g., package upgrade) */
export interface RemediationAction {
  type: string;
  package_name: string;
  current_version: string;
  target_version: string;
  ecosystem: string;
}

/** A vulnerability resolved by a triage path */
export interface ResolvedVulnEntry {
  vulnerability_id: string;
  priority_level: PriorityLevel;
  composite_score: number;
  fixed_version: string;
}

/** Server profile binding */
export interface ServerProfileBinding {
  id: string;
  project_id: string;
  server_label: string;
  environment: string;
  profile_name: string;
  description: string;
  created_at: string;
  updated_at: string;
}

/** Request to create/update a profile binding */
export interface ProfileBindingRequest {
  profile_name: string;
  description?: string;
}

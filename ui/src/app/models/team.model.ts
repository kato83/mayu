export interface Team {
  id: number;
  name: string;
  description?: string;
  created_at: string;
  updated_at: string;
}

export interface TeamMember {
  id: number;
  team_id: number;
  user_id: number;
  role: string;
  email?: string;
  name?: string;
}

export interface CreateTeamInput {
  name: string;
  description?: string;
}

export interface UpdateTeamInput {
  name?: string;
  description?: string;
}

export interface AddMemberInput {
  user_id: number;
  role: string;
}

export interface UserInfo {
  id: number;
  email: string;
  name: string;
}

export interface TeamDashboardSummary {
  team_id: number;
  team_name: string;
  total_projects: number;
  total_findings: number;
  by_severity: { critical: number; high: number; medium: number; low: number };
  top_projects: ProjectRiskSummary[];
  recent_scans: RecentScanSummary[];
  kev_exposure: number;
}

export interface ProjectRiskSummary {
  project_id: number;
  project_name: string;
  critical: number;
  high: number;
  medium: number;
  low: number;
  total: number;
}

export interface RecentScanSummary {
  project_name: string;
  version: string;
  scanned_at: string;
  total_findings: number;
  new_findings: number;
}

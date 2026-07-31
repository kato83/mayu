import { HttpClient } from '@angular/common/http';
import { Injectable, inject } from '@angular/core';
import type { Observable } from 'rxjs';
import { map } from 'rxjs/operators';
import type {
  CrossProjectTriageResult,
  ProfileBindingRequest,
  ServerProfileBinding,
  TriageOverviewSummary,
  TriagePath,
  TriageProfile,
  TriageResult,
  TriageSummary,
} from '../models/triage.model';

@Injectable({ providedIn: 'root' })
export class TriageService {
  private readonly http = inject(HttpClient);

  // --- Dashboard ---

  getDashboardSummary(): Observable<TriageSummary> {
    return this.http.get<TriageSummary>('/api/v1/dashboard/triage');
  }

  // --- Single vulnerability triage ---

  getVulnerabilityTriage(vulnId: string, profile?: string): Observable<TriageResult> {
    const params: Record<string, string> = {};
    if (profile) {
      params['profile'] = profile;
    }
    return this.http.get<TriageResult>(`/api/v1/vulnerabilities/${vulnId}/triage`, { params });
  }

  // --- Batch triage ---

  triageBatch(request: { vulnerability_ids?: string[]; project_id?: string }): Observable<TriageResult[]> {
    return this.http.post<TriageResult[]>('/api/v1/triage', request);
  }

  // --- Project triage ---

  getProjectTriage(
    projectId: string,
    options?: { profile?: string; limit?: number; priority?: string },
  ): Observable<TriageResult[]> {
    const params: Record<string, string> = {};
    if (options?.profile) params['profile'] = options.profile;
    if (options?.limit) params['limit'] = String(options.limit);
    if (options?.priority) params['priority'] = options.priority;
    return this.http
      .get<{ results: TriageResult[] }>(`/api/v1/sbom/projects/${projectId}/triage`, { params })
      .pipe(map((res) => res.results ?? []));
  }

  // --- Profiles ---

  listProfiles(): Observable<TriageProfile[]> {
    return this.http.get<{ profiles: TriageProfile[] }>('/api/v1/triage/profiles').pipe(map((res) => res.profiles));
  }

  validateProfile(profile: TriageProfile): Observable<{ valid: boolean; errors: string[] }> {
    return this.http.post<{ valid: boolean; errors: string[] }>('/api/v1/triage/profiles/validate', profile);
  }

  // --- Cross-project overview ---

  getOverviewSummary(): Observable<TriageOverviewSummary> {
    return this.http.get<TriageOverviewSummary>('/api/v1/triage/overview/summary');
  }

  getOverviewVulnerabilities(options?: {
    priority?: string;
    limit?: number;
    sort?: string;
  }): Observable<CrossProjectTriageResult[]> {
    const params: Record<string, string> = {};
    if (options?.priority) params['priority'] = options.priority;
    if (options?.limit) params['limit'] = String(options.limit);
    if (options?.sort) params['sort'] = options.sort;
    return this.http
      .get<{ vulnerabilities: CrossProjectTriageResult[] }>('/api/v1/triage/overview/vulnerabilities', { params })
      .pipe(map((res) => res.vulnerabilities ?? []));
  }

  // --- Triage Paths ---

  listPaths(options?: {
    limit?: number;
    priority?: string;
    ecosystem?: string;
    project?: string;
  }): Observable<TriagePath[]> {
    const params: Record<string, string> = {};
    if (options?.limit) params['limit'] = String(options.limit);
    if (options?.priority) params['priority'] = options.priority;
    if (options?.ecosystem) params['ecosystem'] = options.ecosystem;
    if (options?.project) params['project'] = options.project;
    return this.http
      .get<{ paths: TriagePath[] }>('/api/v1/triage/paths', { params })
      .pipe(map((res) => res.paths ?? []));
  }

  getPath(id: string): Observable<TriagePath> {
    return this.http.get<TriagePath>(`/api/v1/triage/paths/${id}`);
  }

  getProjectPaths(projectId: string): Observable<TriagePath[]> {
    return this.http
      .get<{ paths: TriagePath[] }>(`/api/v1/sbom/projects/${projectId}/triage/paths`)
      .pipe(map((res) => res.paths ?? []));
  }

  // --- Server Profile Bindings ---

  listBindings(projectId: string): Observable<ServerProfileBinding[]> {
    return this.http
      .get<{ servers: ServerProfileBinding[] }>(`/api/v1/sbom/projects/${projectId}/servers`)
      .pipe(map((res) => res.servers ?? []));
  }

  setBinding(projectId: string, serverLabel: string, request: ProfileBindingRequest): Observable<void> {
    return this.http.put<void>(`/api/v1/sbom/projects/${projectId}/servers/${serverLabel}/profile`, request);
  }

  deleteBinding(projectId: string, serverLabel: string): Observable<void> {
    return this.http.delete<void>(`/api/v1/sbom/projects/${projectId}/servers/${serverLabel}/profile`);
  }
}

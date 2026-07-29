import { HttpClient } from '@angular/common/http';
import { Injectable, inject } from '@angular/core';
import type { Observable } from 'rxjs';

import type {
  CreateProjectRequest,
  FindingStatusEntry,
  FindingStatusUpdate,
  SBOMProject,
  SBOMScanResult,
  SBOMVersion,
  ScanDiff,
  UploadSBOMResponse,
} from '../models/sbom.model';

@Injectable({
  providedIn: 'root',
})
export class SbomService {
  private readonly http = inject(HttpClient);
  private readonly baseUrl = '/api/v1/sbom';

  /**
   * List all SBOM projects for the current user.
   */
  listProjects(): Observable<SBOMProject[]> {
    return this.http.get<SBOMProject[]>(`${this.baseUrl}/projects`, { withCredentials: true });
  }

  /**
   * Get a single SBOM project by ID.
   */
  getProject(id: number): Observable<SBOMProject> {
    return this.http.get<SBOMProject>(`${this.baseUrl}/projects/${id}`, { withCredentials: true });
  }

  /**
   * Create a new SBOM project.
   */
  createProject(name: string, teamId?: number): Observable<SBOMProject> {
    const req: CreateProjectRequest = { name, team_id: teamId || undefined };
    return this.http.post<SBOMProject>(`${this.baseUrl}/projects`, req, { withCredentials: true });
  }

  /**
   * Delete an SBOM project by ID.
   */
  deleteProject(id: number): Observable<void> {
    return this.http.delete<void>(`${this.baseUrl}/projects/${id}`, { withCredentials: true });
  }

  /**
   * Update an SBOM project (name, team_id).
   */
  updateProject(id: number, body: { name?: string; team_id?: number | null }): Observable<SBOMProject> {
    return this.http.put<SBOMProject>(`${this.baseUrl}/projects/${id}`, body, { withCredentials: true });
  }

  /**
   * Upload an SBOM file and trigger a scan.
   */
  uploadSBOM(projectId: number, version: string, environment: string, sbom: object): Observable<UploadSBOMResponse> {
    const body = { version, environment, sbom };
    return this.http.post<UploadSBOMResponse>(`${this.baseUrl}/projects/${projectId}/versions`, body, {
      withCredentials: true,
    });
  }

  /**
   * List versions for a project.
   */
  listVersions(projectId: number): Observable<SBOMVersion[]> {
    return this.http.get<SBOMVersion[]>(`${this.baseUrl}/projects/${projectId}/versions`, { withCredentials: true });
  }

  /**
   * List scan results for a version.
   */
  listScanResults(versionId: number): Observable<SBOMScanResult[]> {
    return this.http.get<SBOMScanResult[]>(`${this.baseUrl}/versions/${versionId}/scans`, { withCredentials: true });
  }

  /**
   * Trigger a rescan of an existing SBOM version.
   */
  rescanVersion(versionId: number): Observable<SBOMScanResult> {
    return this.http.post<SBOMScanResult>(`${this.baseUrl}/versions/${versionId}/scans`, {}, { withCredentials: true });
  }

  /**
   * Get a single scan result by ID.
   */
  getScanResult(id: number): Observable<SBOMScanResult> {
    return this.http.get<SBOMScanResult>(`${this.baseUrl}/scans/${id}`, { withCredentials: true });
  }

  /**
   * Get the diff between a scan result and its predecessor.
   */
  getScanDiff(scanId: number): Observable<ScanDiff> {
    return this.http.get<ScanDiff>(`${this.baseUrl}/scans/${scanId}/diff`, { withCredentials: true });
  }

  /**
   * Update the status of a finding in a scan.
   */
  updateFindingStatus(scanId: number, vulnId: string, body: FindingStatusUpdate): Observable<FindingStatusEntry> {
    return this.http.put<FindingStatusEntry>(
      `${this.baseUrl}/scans/${scanId}/findings/${encodeURIComponent(vulnId)}/status`,
      body,
      { withCredentials: true },
    );
  }

  /**
   * List finding statuses for a scan, optionally filtered by status values.
   */
  listFindingStatuses(scanId: number, statusFilter?: string[]): Observable<FindingStatusEntry[]> {
    let url = `${this.baseUrl}/scans/${scanId}/findings/statuses`;
    if (statusFilter && statusFilter.length > 0) {
      url += `?status=${statusFilter.join(',')}`;
    }
    return this.http.get<FindingStatusEntry[]>(url, { withCredentials: true });
  }
}

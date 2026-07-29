import { Injectable, inject } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { Observable } from 'rxjs';
import {
  Team,
  TeamMember,
  CreateTeamInput,
  UpdateTeamInput,
  AddMemberInput,
  TeamDashboardSummary,
  UserInfo,
} from '../models/team.model';

@Injectable({ providedIn: 'root' })
export class TeamService {
  private readonly http = inject(HttpClient);
  private readonly baseUrl = '/api/v1/teams';

  /** List all teams visible to the current user. */
  list(): Observable<Team[]> {
    return this.http.get<Team[]>(this.baseUrl, { withCredentials: true });
  }

  /** Get a team by ID. */
  get(id: number): Observable<Team> {
    return this.http.get<Team>(`${this.baseUrl}/${id}`, { withCredentials: true });
  }

  /** Create a new team. */
  create(input: CreateTeamInput): Observable<Team> {
    return this.http.post<Team>(this.baseUrl, input, { withCredentials: true });
  }

  /** Update a team. */
  update(id: number, input: UpdateTeamInput): Observable<Team> {
    return this.http.put<Team>(`${this.baseUrl}/${id}`, input, { withCredentials: true });
  }

  /** Delete a team. */
  delete(id: number): Observable<void> {
    return this.http.delete<void>(`${this.baseUrl}/${id}`, { withCredentials: true });
  }

  /** List members of a team. */
  listMembers(teamId: number): Observable<TeamMember[]> {
    return this.http.get<TeamMember[]>(`${this.baseUrl}/${teamId}/members`, { withCredentials: true });
  }

  /** Add a member to a team. */
  addMember(teamId: number, input: AddMemberInput): Observable<void> {
    return this.http.post<void>(`${this.baseUrl}/${teamId}/members`, input, { withCredentials: true });
  }

  /** Remove a member from a team. */
  removeMember(teamId: number, userId: number): Observable<void> {
    return this.http.delete<void>(`${this.baseUrl}/${teamId}/members/${userId}`, { withCredentials: true });
  }

  /** Get team-scoped dashboard summary. */
  getTeamDashboard(teamId: number): Observable<TeamDashboardSummary> {
    return this.http.get<TeamDashboardSummary>(`/api/v1/dashboard/team-summary?team_id=${teamId}`, {
      withCredentials: true,
    });
  }

  /** List all users (for member add datalist). */
  listUsers(): Observable<UserInfo[]> {
    return this.http.get<UserInfo[]>(`${this.baseUrl}/users`, { withCredentials: true });
  }
}

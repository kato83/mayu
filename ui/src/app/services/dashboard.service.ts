import { Injectable, inject } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { Observable } from 'rxjs';
import {
  DashboardSummary,
  DashboardTrends,
  DashboardDistributions,
  DashboardTopRisks,
} from '../models/dashboard.model';

@Injectable({ providedIn: 'root' })
export class DashboardService {
  private readonly http = inject(HttpClient);

  getSummary(): Observable<DashboardSummary> {
    return this.http.get<DashboardSummary>('/api/v1/dashboard/summary');
  }

  getTrends(days: number = 30): Observable<DashboardTrends> {
    return this.http.get<DashboardTrends>(
      `/api/v1/dashboard/trends?days=${days}`,
    );
  }

  getDistributions(): Observable<DashboardDistributions> {
    return this.http.get<DashboardDistributions>(
      '/api/v1/dashboard/distributions',
    );
  }

  getTopRisks(limit: number = 10): Observable<DashboardTopRisks> {
    return this.http.get<DashboardTopRisks>(
      `/api/v1/dashboard/top-risks?limit=${limit}`,
    );
  }
}

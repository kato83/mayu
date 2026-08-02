import { HttpClient, HttpParams } from '@angular/common/http';
import { Injectable, inject } from '@angular/core';
import type { Observable } from 'rxjs';

export interface EpssTrendingEntry {
  vulnerability_id: string;
  cve_id: string;
  current_epss: number;
  previous_epss: number;
  delta: number;
  current_percentile: number;
  severity: string;
  summary: string;
}

export interface EpssTrendingResponse {
  entries: EpssTrendingEntry[];
  query: {
    days: number;
    threshold: number;
    limit: number;
  };
  latest_date: string;
  previous_date: string;
  expected_previous_date: string;
  stale: boolean;
  previous_date_missing: boolean;
  previous_date_approximate: boolean;
}

@Injectable({ providedIn: 'root' })
export class EpssTrendingService {
  private readonly http = inject(HttpClient);

  getTrending(params: { days?: number; threshold?: number; limit?: number } = {}): Observable<EpssTrendingResponse> {
    let httpParams = new HttpParams();
    if (params.days !== undefined) {
      httpParams = httpParams.set('days', params.days.toString());
    }
    if (params.threshold !== undefined) {
      httpParams = httpParams.set('threshold', params.threshold.toString());
    }
    if (params.limit !== undefined) {
      httpParams = httpParams.set('limit', params.limit.toString());
    }
    return this.http.get<EpssTrendingResponse>('/api/v1/epss/trending', { params: httpParams });
  }
}

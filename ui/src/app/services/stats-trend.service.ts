import { Injectable, inject } from '@angular/core';
import { HttpClient, HttpParams } from '@angular/common/http';
import { Observable } from 'rxjs';

import { StatsTrendResponse } from '../models/stats-trend.model';

@Injectable({ providedIn: 'root' })
export class StatsTrendService {
  private readonly http = inject(HttpClient);

  getTrend(params: {
    range?: string;
    project_id?: number;
    group_by?: string;
    metric?: string;
  } = {}): Observable<StatsTrendResponse> {
    let httpParams = new HttpParams();
    if (params.range !== undefined) {
      httpParams = httpParams.set('range', params.range);
    }
    if (params.project_id !== undefined) {
      httpParams = httpParams.set('project_id', params.project_id.toString());
    }
    if (params.group_by !== undefined) {
      httpParams = httpParams.set('group_by', params.group_by);
    }
    if (params.metric !== undefined) {
      httpParams = httpParams.set('metric', params.metric);
    }
    return this.http.get<StatsTrendResponse>('/api/v1/stats/trend', { params: httpParams });
  }
}

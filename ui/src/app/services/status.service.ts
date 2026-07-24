import { inject, Injectable } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { Observable } from 'rxjs';

import { StatusResponse } from '../models/status.model';

@Injectable({
  providedIn: 'root',
})
export class StatusService {
  private readonly http = inject(HttpClient);
  private readonly baseUrl = '/api/v1/status';

  /**
   * Get data source sync status and EPSS coverage information.
   */
  getStatus(): Observable<StatusResponse> {
    return this.http.get<StatusResponse>(this.baseUrl);
  }
}

import { HttpClient } from '@angular/common/http';
import { Injectable, inject } from '@angular/core';
import type { Observable } from 'rxjs';

import type { VersionResponse } from '../models/version.model';

@Injectable({
  providedIn: 'root',
})
export class VersionService {
  private readonly http = inject(HttpClient);
  private readonly baseUrl = '/api/v1/version';

  /**
   * Get the application version.
   */
  getVersion(): Observable<VersionResponse> {
    return this.http.get<VersionResponse>(this.baseUrl);
  }
}

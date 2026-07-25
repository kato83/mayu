import { inject, Injectable } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { Observable } from 'rxjs';

import { VersionResponse } from '../models/version.model';

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

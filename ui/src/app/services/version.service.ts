import { inject, Injectable } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { Observable } from 'rxjs';

export interface VersionResponse {
  version: string;
}

@Injectable({
  providedIn: 'root',
})
export class VersionService {
  private readonly http = inject(HttpClient);
  private readonly baseUrl = '/api/v1/version';

  /**
   * Get the application version from the API.
   */
  getVersion(): Observable<VersionResponse> {
    return this.http.get<VersionResponse>(this.baseUrl);
  }
}

import { Injectable, inject } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { Observable } from 'rxjs';

export interface APIKey {
  id: number;
  name: string;
  key_prefix: string;
  created_at: string;
  expires_at?: string;
}

export interface CreateAPIKeyResponse {
  key: string;
  api_key: APIKey;
}

@Injectable({
  providedIn: 'root',
})
export class ApiKeyService {
  private readonly http = inject(HttpClient);
  private readonly baseUrl = '/api/v1/user/api-keys';

  /**
   * List all API keys for the current user.
   */
  list(): Observable<APIKey[]> {
    return this.http.get<APIKey[]>(this.baseUrl, { withCredentials: true });
  }

  /**
   * Create a new API key.
   */
  create(name: string, expiresInDays?: number): Observable<CreateAPIKeyResponse> {
    const body: { name: string; expires_in_days?: number } = { name };
    if (expiresInDays != null) {
      body.expires_in_days = expiresInDays;
    }
    return this.http.post<CreateAPIKeyResponse>(this.baseUrl, body, { withCredentials: true });
  }

  /**
   * Delete an API key by ID.
   */
  delete(id: number): Observable<void> {
    return this.http.delete<void>(`${this.baseUrl}/${id}`, { withCredentials: true });
  }
}

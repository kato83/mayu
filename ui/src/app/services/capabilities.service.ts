import { HttpClient, HttpParams } from '@angular/common/http';
import { Injectable, inject } from '@angular/core';
import type { Observable } from 'rxjs';

export interface FulltextSearchResult {
  id: string;
  summary: string;
  score: number;
}

export interface FulltextSearchResponse {
  results: FulltextSearchResult[];
  total: number;
  limit: number;
  offset: number;
}

export interface Capabilities {
  fulltext_search: {
    available: boolean;
    engine: string;
  };
  translation: {
    available: boolean;
  };
}

@Injectable({ providedIn: 'root' })
export class CapabilitiesService {
  private readonly http = inject(HttpClient);
  private readonly baseUrl = '/api/v1';

  getCapabilities(): Observable<Capabilities> {
    return this.http.get<Capabilities>(`${this.baseUrl}/capabilities`);
  }

  fulltextSearch(query: string, ecosystem?: string, limit = 20, offset = 0): Observable<FulltextSearchResponse> {
    let params = new HttpParams().set('q', query).set('limit', limit.toString()).set('offset', offset.toString());
    if (ecosystem) {
      params = params.set('ecosystem', ecosystem);
    }
    return this.http.get<FulltextSearchResponse>(`${this.baseUrl}/search/fulltext`, { params });
  }
}

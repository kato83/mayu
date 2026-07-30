import { HttpClient } from '@angular/common/http';
import { Injectable, inject } from '@angular/core';
import type { Observable } from 'rxjs';

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
}

import { HttpClient, HttpParams } from '@angular/common/http';
import { Injectable, inject } from '@angular/core';
import type { Observable } from 'rxjs';

import type {
  CreateWatchlistRequest,
  UpdateWatchlistRequest,
  Watchlist,
  WatchlistMatchesResponse,
} from '../models/watchlist.model';

@Injectable({
  providedIn: 'root',
})
export class WatchlistService {
  private readonly http = inject(HttpClient);
  private readonly baseUrl = '/api/v1/watchlists';

  /**
   * List all watchlists for the current user.
   */
  list(): Observable<Watchlist[]> {
    return this.http.get<Watchlist[]>(this.baseUrl, { withCredentials: true });
  }

  /**
   * Get a single watchlist by ID.
   */
  get(id: number): Observable<Watchlist> {
    return this.http.get<Watchlist>(`${this.baseUrl}/${id}`, { withCredentials: true });
  }

  /**
   * Create a new watchlist.
   */
  create(req: CreateWatchlistRequest): Observable<Watchlist> {
    return this.http.post<Watchlist>(this.baseUrl, req, { withCredentials: true });
  }

  /**
   * Update an existing watchlist.
   */
  update(id: number, req: UpdateWatchlistRequest): Observable<Watchlist> {
    return this.http.put<Watchlist>(`${this.baseUrl}/${id}`, req, { withCredentials: true });
  }

  /**
   * Delete a watchlist by ID.
   */
  delete(id: number): Observable<void> {
    return this.http.delete<void>(`${this.baseUrl}/${id}`, { withCredentials: true });
  }

  /**
   * List matches for a specific watchlist.
   */
  listMatches(watchlistId: number, limit?: number, offset?: number): Observable<WatchlistMatchesResponse> {
    let params = new HttpParams();
    if (limit != null) {
      params = params.set('limit', limit.toString());
    }
    if (offset != null) {
      params = params.set('offset', offset.toString());
    }
    return this.http.get<WatchlistMatchesResponse>(`${this.baseUrl}/${watchlistId}/matches`, {
      withCredentials: true,
      params,
    });
  }

  /**
   * List all matches for the current user across all watchlists.
   */
  listUserMatches(limit?: number, offset?: number): Observable<WatchlistMatchesResponse> {
    let params = new HttpParams();
    if (limit != null) {
      params = params.set('limit', limit.toString());
    }
    if (offset != null) {
      params = params.set('offset', offset.toString());
    }
    return this.http.get<WatchlistMatchesResponse>(`${this.baseUrl}/matches`, {
      withCredentials: true,
      params,
    });
  }
}

import { HttpClient } from '@angular/common/http';
import { Injectable, inject } from '@angular/core';
import type { Observable } from 'rxjs';

export interface Webhook {
  id: number;
  name: string;
  url: string;
  events: string[];
  content_type: string;
  body_template: string;
  secret?: string;
  enabled: boolean;
  team_id?: number;
  created_at: string;
  updated_at: string;
}

export interface WebhookDeliveryLog {
  id: number;
  webhook_id: number;
  event: string;
  payload?: string;
  response_status?: number;
  response_body?: string;
  error_message?: string;
  attempt: number;
  delivered_at: string;
  duration_ms?: number;
}

export interface TestWebhookResponse {
  success: boolean;
  status_code?: number;
  error?: string;
}

@Injectable({
  providedIn: 'root',
})
export class WebhookService {
  private readonly http = inject(HttpClient);
  private readonly baseUrl = '/api/v1/webhooks';

  /**
   * List all webhooks.
   */
  list(): Observable<Webhook[]> {
    return this.http.get<Webhook[]>(this.baseUrl, { withCredentials: true });
  }

  /**
   * Create a new webhook.
   */
  create(webhook: Partial<Webhook>): Observable<Webhook> {
    return this.http.post<Webhook>(this.baseUrl, webhook, { withCredentials: true });
  }

  /**
   * Get a webhook by ID.
   */
  get(id: number): Observable<Webhook> {
    return this.http.get<Webhook>(`${this.baseUrl}/${id}`, { withCredentials: true });
  }

  /**
   * Update a webhook by ID.
   */
  update(id: number, webhook: Partial<Webhook>): Observable<Webhook> {
    return this.http.put<Webhook>(`${this.baseUrl}/${id}`, webhook, { withCredentials: true });
  }

  /**
   * Delete a webhook by ID.
   */
  delete(id: number): Observable<void> {
    return this.http.delete<void>(`${this.baseUrl}/${id}`, { withCredentials: true });
  }

  /**
   * Get delivery logs for a webhook.
   */
  getDeliveries(id: number, limit?: number): Observable<WebhookDeliveryLog[]> {
    const params: { limit?: string } = {};
    if (limit != null) {
      params.limit = String(limit);
    }
    return this.http.get<WebhookDeliveryLog[]>(`${this.baseUrl}/${id}/deliveries`, {
      params,
      withCredentials: true,
    });
  }

  /**
   * Send a test webhook.
   */
  test(id: number): Observable<TestWebhookResponse> {
    return this.http.post<TestWebhookResponse>(`${this.baseUrl}/${id}/test`, {}, { withCredentials: true });
  }
}

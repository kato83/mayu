import { inject, Injectable } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { Observable } from 'rxjs';

import { IngestParams, IngestEvent, IngestStartResponse, IngestJobsResponse, IngestJobDetail } from '../models/ingest.model';

@Injectable({
  providedIn: 'root',
})
export class IngestService {
  private readonly http = inject(HttpClient);
  private readonly baseUrl = '/api/v1/ingest';

  /**
   * Start an ingest operation via POST. Returns the job ID immediately.
   * The ingest runs in the background on the server — page navigation
   * does not cancel it.
   */
  startIngest(params: IngestParams): Observable<IngestStartResponse> {
    const body: Record<string, string> = { type: params.type };
    if (params.ecosystem) {
      body['ecosystem'] = params.ecosystem;
    }
    if (params.repo) {
      body['repo'] = params.repo;
    }
    if (params.from) {
      body['from'] = params.from;
    }
    if (params.to) {
      body['to'] = params.to;
    }
    return this.http.post<IngestStartResponse>(this.baseUrl, body);
  }

  /**
   * Stream progress events for an ingest job via SSE.
   * Supports late-joining: if the job is still running, events are sent from
   * the beginning. If the job has already finished, a single final event is sent.
   *
   * The Observable completes when the job finishes (phase 'done' or 'error').
   * Unsubscribing aborts the SSE connection but does NOT cancel the server-side job.
   */
  streamProgress(jobId: number): Observable<IngestEvent> {
    return new Observable<IngestEvent>((subscriber) => {
      const controller = new AbortController();
      const url = `${this.baseUrl}/jobs/${jobId}/stream`;

      fetch(url, {
        method: 'GET',
        headers: { Accept: 'text/event-stream' },
        signal: controller.signal,
      })
        .then((response) => {
          if (!response.ok) {
            throw new Error(`HTTP ${response.status}: ${response.statusText}`);
          }
          if (!response.body) {
            throw new Error('Response body is null');
          }
          return this.readSSEStream(response.body, subscriber);
        })
        .catch((err) => {
          if (err.name !== 'AbortError') {
            subscriber.error(err);
          }
        });

      // Teardown: abort fetch on unsubscribe (does NOT cancel server-side job)
      return () => {
        controller.abort();
      };
    });
  }

  private async readSSEStream(
    body: ReadableStream<Uint8Array>,
    subscriber: { next: (value: IngestEvent) => void; complete: () => void; error: (err: unknown) => void },
  ): Promise<void> {
    const reader = body.getReader();
    const decoder = new TextDecoder();
    let buffer = '';

    try {
      while (true) {
        const { done, value } = await reader.read();
        if (done) {
          break;
        }

        buffer += decoder.decode(value, { stream: true });
        const lines = buffer.split('\n');
        // Keep the last incomplete line in the buffer
        buffer = lines.pop() ?? '';

        for (const line of lines) {
          if (line.startsWith('data: ')) {
            const jsonStr = line.slice(6).trim();
            if (jsonStr) {
              try {
                const event: IngestEvent = JSON.parse(jsonStr);
                subscriber.next(event);
                if (event.phase === 'done' || event.phase === 'error') {
                  subscriber.complete();
                  return;
                }
              } catch {
                // Skip malformed JSON lines
              }
            }
          }
        }
      }
      subscriber.complete();
    } catch (err) {
      subscriber.error(err);
    }
  }

  /**
   * List recent ingest jobs.
   */
  listJobs(limit: number = 20): Observable<IngestJobsResponse> {
    return this.http.get<IngestJobsResponse>(`${this.baseUrl}/jobs`, {
      params: { limit: limit.toString() },
    });
  }

  /**
   * Get a single ingest job detail including failures.
   */
  getJob(id: number): Observable<IngestJobDetail> {
    return this.http.get<IngestJobDetail>(`${this.baseUrl}/jobs/${id}`);
  }
}

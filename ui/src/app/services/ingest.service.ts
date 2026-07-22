import { Injectable } from '@angular/core';
import { Observable } from 'rxjs';

import { IngestParams, IngestEvent } from '../models/ingest.model';

@Injectable({
  providedIn: 'root',
})
export class IngestService {
  private readonly baseUrl = '/api/v1/ingest';

  /**
   * Start an ingest operation via POST and stream SSE progress events.
   * Uses fetch API + ReadableStream since EventSource only supports GET.
   */
  startIngest(params: IngestParams): Observable<IngestEvent> {
    return new Observable<IngestEvent>((subscriber) => {
      const controller = new AbortController();

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

      fetch(this.baseUrl, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Accept': 'text/event-stream',
        },
        body: JSON.stringify(body),
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

      // Teardown: abort fetch on unsubscribe
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
}

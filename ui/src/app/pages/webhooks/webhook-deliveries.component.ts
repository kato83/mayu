import { Component, inject, signal, OnInit } from '@angular/core';
import { ActivatedRoute, RouterLink } from '@angular/router';
import { DatePipe } from '@angular/common';

import { WebhookService, WebhookDeliveryLog } from '../../services/webhook.service';

@Component({
  selector: 'app-webhook-deliveries',
  standalone: true,
  imports: [DatePipe, RouterLink],
  template: `
    <div class="p-6">
      <div class="flex items-center gap-4 mb-6">
        <a
          routerLink="/webhooks"
          class="px-3 py-1.5 bg-slate-200 dark:bg-slate-700 hover:bg-slate-300 dark:hover:bg-slate-600 text-slate-700 dark:text-slate-300 text-sm font-medium rounded-md transition-colors"
          i18n="@@webhooks.deliveries.backButton"
        >
          Back to Webhooks
        </a>
        <h1 class="text-2xl font-bold text-slate-900 dark:text-white" i18n="@@webhooks.deliveries.title">
          Delivery Logs
        </h1>
      </div>

      @if (loading()) {
        <p class="text-slate-500 dark:text-slate-400" i18n="@@webhooks.deliveries.loading">Loading...</p>
      } @else if (deliveries().length === 0) {
        <p class="text-slate-500 dark:text-slate-400" i18n="@@webhooks.deliveries.noLogs">
          No delivery logs found for this webhook.
        </p>
      } @else {
        <div class="overflow-x-auto">
          <table class="w-full text-sm text-left">
            <thead class="text-xs uppercase bg-slate-50 dark:bg-slate-800 text-slate-600 dark:text-slate-400">
              <tr>
                <th class="px-4 py-3 whitespace-nowrap" i18n="@@webhooks.deliveries.col.event">Event</th>
                <th class="px-4 py-3 whitespace-nowrap" i18n="@@webhooks.deliveries.col.status">Status</th>
                <th class="px-4 py-3 whitespace-nowrap" i18n="@@webhooks.deliveries.col.attempt">Attempt</th>
                <th class="px-4 py-3 whitespace-nowrap" i18n="@@webhooks.deliveries.col.deliveredAt">Delivered At</th>
                <th class="px-4 py-3 whitespace-nowrap" i18n="@@webhooks.deliveries.col.duration">Duration (ms)</th>
                <th class="px-4 py-3 whitespace-nowrap" i18n="@@webhooks.deliveries.col.error">Error</th>
              </tr>
            </thead>
            <tbody>
              @for (delivery of deliveries(); track delivery.id) {
                <tr class="border-b border-slate-200 dark:border-slate-700">
                  <td class="px-4 py-3 text-slate-900 dark:text-white">
                    <span class="inline-block px-2 py-0.5 text-xs font-medium rounded-full bg-blue-100 dark:bg-blue-900/30 text-blue-800 dark:text-blue-200">
                      {{ delivery.event }}
                    </span>
                  </td>
                  <td class="px-4 py-3">
                    @if (delivery.response_status) {
                      <span
                        class="inline-block px-2 py-0.5 text-xs font-medium rounded-full"
                        [class]="getStatusClasses(delivery.response_status)"
                      >
                        {{ delivery.response_status }}
                      </span>
                    } @else {
                      <span class="text-slate-400">-</span>
                    }
                  </td>
                  <td class="px-4 py-3 text-slate-600 dark:text-slate-400">{{ delivery.attempt }}</td>
                  <td class="px-4 py-3 text-slate-600 dark:text-slate-400">{{ delivery.delivered_at | date:'short' }}</td>
                  <td class="px-4 py-3 text-slate-600 dark:text-slate-400">
                    @if (delivery.duration_ms != null) {
                      {{ delivery.duration_ms }}
                    } @else {
                      -
                    }
                  </td>
                  <td class="px-4 py-3 text-red-600 dark:text-red-400 text-xs max-w-xs truncate">
                    {{ delivery.error_message || '-' }}
                  </td>
                </tr>
              }
            </tbody>
          </table>
        </div>
      }
    </div>
  `,
})
export class WebhookDeliveriesComponent implements OnInit {
  private readonly route = inject(ActivatedRoute);
  private readonly webhookService = inject(WebhookService);

  readonly deliveries = signal<WebhookDeliveryLog[]>([]);
  readonly loading = signal(true);

  ngOnInit(): void {
    const id = Number(this.route.snapshot.paramMap.get('id'));
    if (id) {
      this.loadDeliveries(id);
    }
  }

  private loadDeliveries(webhookId: number): void {
    this.loading.set(true);
    this.webhookService.getDeliveries(webhookId, 100).subscribe({
      next: (deliveries) => {
        this.deliveries.set(deliveries);
        this.loading.set(false);
      },
      error: () => {
        this.loading.set(false);
      },
    });
  }

  getStatusClasses(status: number): string {
    if (status >= 200 && status < 300) {
      return 'bg-green-100 dark:bg-green-900/30 text-green-800 dark:text-green-200';
    }
    if (status >= 400) {
      return 'bg-red-100 dark:bg-red-900/30 text-red-800 dark:text-red-200';
    }
    return 'bg-slate-100 dark:bg-slate-700 text-slate-600 dark:text-slate-400';
  }
}

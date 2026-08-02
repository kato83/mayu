import { DecimalPipe } from '@angular/common';
import { Component, DestroyRef, inject, type OnInit, signal } from '@angular/core';
import { takeUntilDestroyed } from '@angular/core/rxjs-interop';
import { RouterLink } from '@angular/router';

import { type EpssTrendingEntry, EpssTrendingService } from '../../services/epss-trending.service';

@Component({
  selector: 'app-epss-trending',
  standalone: true,
  imports: [RouterLink, DecimalPipe],
  template: `
    <div class="space-y-6">
      <div class="flex flex-col sm:flex-row sm:items-center sm:justify-end gap-4">
        <div class="flex flex-wrap gap-4 items-center">
          <!-- Days selector -->
          <div class="flex items-center gap-2">
            <span class="text-sm text-slate-500 dark:text-slate-400" i18n="@@epssTrending.periodLabel">Period:</span>
            <div class="flex gap-1">
              @for (opt of daysOptions; track opt.value) {
                <button
                  (click)="onDaysChange(opt.value)"
                  [class]="selectedDays() === opt.value ? 'px-2 py-1 text-xs font-medium rounded bg-indigo-600 text-white cursor-pointer' : 'px-2 py-1 text-xs font-medium rounded bg-slate-100 dark:bg-slate-700 text-slate-600 dark:text-slate-300 hover:bg-slate-200 dark:hover:bg-slate-600 cursor-pointer'"
                >{{ opt.label }}</button>
              }
            </div>
          </div>
          <!-- Threshold selector -->
          <div class="flex items-center gap-2">
            <span class="text-sm text-slate-500 dark:text-slate-400" i18n="@@epssTrending.thresholdLabel">Threshold:</span>
            <div class="flex gap-1">
              @for (opt of thresholdOptions; track opt.value) {
                <button
                  (click)="onThresholdChange(opt.value)"
                  [class]="selectedThreshold() === opt.value ? 'px-2 py-1 text-xs font-medium rounded bg-indigo-600 text-white cursor-pointer' : 'px-2 py-1 text-xs font-medium rounded bg-slate-100 dark:bg-slate-700 text-slate-600 dark:text-slate-300 hover:bg-slate-200 dark:hover:bg-slate-600 cursor-pointer'"
                >{{ opt.label }}</button>
              }
            </div>
          </div>
        </div>
      </div>

      <!-- Stale data warning -->
      @if (stale()) {
        <div role="alert" class="rounded-md bg-amber-50 dark:bg-amber-900/20 border border-amber-200 dark:border-amber-700 p-4">
          <div class="flex">
            <div class="flex-shrink-0">
              <svg class="h-5 w-5 text-amber-400" viewBox="0 0 20 20" fill="currentColor">
                <path fill-rule="evenodd" d="M8.485 2.495c.673-1.167 2.357-1.167 3.03 0l6.28 10.875c.673 1.167-.17 2.625-1.516 2.625H3.72c-1.347 0-2.189-1.458-1.515-2.625L8.485 2.495zM10 6a.75.75 0 01.75.75v3.5a.75.75 0 01-1.5 0v-3.5A.75.75 0 0110 6zm0 9a1 1 0 100-2 1 1 0 000 2z" clip-rule="evenodd" />
              </svg>
            </div>
            <div class="ml-3">
              <p class="text-sm text-amber-700 dark:text-amber-300" i18n="@@epssTrending.staleWarning">
                EPSS data is outdated. The latest score date is {{ latestDate() }}. Run <code class="font-mono bg-amber-100 dark:bg-amber-800/40 px-1 rounded">mayu ingest --source epss --update</code> to refresh.
              </p>
            </div>
          </div>
        </div>
      }

      <!-- Comparison dates -->
      @if (!loading() && latestDate() && !previousDateMissing()) {
        <div class="text-sm text-slate-500 dark:text-slate-400">
          <span i18n="@@epssTrending.comparingDates">Comparing:</span> <span class="font-mono">{{ latestDate() }}</span> vs <span class="font-mono">{{ previousDate() }}</span>
        </div>
      }

      <!-- Previous date missing warning -->
      @if (previousDateMissing()) {
        <div role="alert" class="rounded-md bg-blue-50 dark:bg-blue-900/20 border border-blue-200 dark:border-blue-700 p-4">
          <div class="flex">
            <div class="flex-shrink-0">
              <svg class="h-5 w-5 text-blue-400" viewBox="0 0 20 20" fill="currentColor">
                <path fill-rule="evenodd" d="M18 10a8 8 0 11-16 0 8 8 0 0116 0zm-7-4a1 1 0 11-2 0 1 1 0 012 0zM9 9a.75.75 0 000 1.5h.253a.25.25 0 01.244.304l-.459 2.066A1.75 1.75 0 0010.747 15H11a.75.75 0 000-1.5h-.253a.25.25 0 01-.244-.304l.459-2.066A1.75 1.75 0 009.253 9H9z" clip-rule="evenodd" />
              </svg>
            </div>
            <div class="ml-3">
              <p class="text-sm text-blue-700 dark:text-blue-300" i18n="@@epssTrending.previousDateMissing">
                No comparison data available for the selected period. EPSS data for {{ selectedDays() }} days ago does not exist. Try a shorter period or run backfill.
              </p>
            </div>
          </div>
        </div>
      }

      <!-- Loading -->
      @if (loading()) {
        <div class="flex items-center justify-center py-12">
          <div class="animate-spin rounded-full h-8 w-8 border-b-2 border-indigo-500"></div>
        </div>
      }

      <!-- Results table -->
      @if (!loading() && entries().length > 0) {
        <div class="bg-white dark:bg-slate-800 rounded-lg border border-slate-200 dark:border-slate-700 shadow-sm overflow-hidden">
          <div class="overflow-x-auto">
            <table class="w-full text-sm text-left">
              <thead>
                <tr class="text-xs text-slate-500 dark:text-slate-400 border-b border-slate-200 dark:border-slate-700 bg-slate-50 dark:bg-slate-800/50">
                  <th class="px-4 py-3 font-medium whitespace-nowrap" i18n="@@epssTrending.colCveId">CVE ID</th>
                  <th class="px-4 py-3 font-medium whitespace-nowrap" i18n="@@epssTrending.colCurrentEpss">Current EPSS</th>
                  <th class="px-4 py-3 font-medium whitespace-nowrap" i18n="@@epssTrending.colPreviousEpss">Previous EPSS</th>
                  <th class="px-4 py-3 font-medium whitespace-nowrap" i18n="@@epssTrending.colDelta">Delta</th>
                  <th class="px-4 py-3 font-medium whitespace-nowrap" i18n="@@epssTrending.colPercentile">Percentile</th>
                  <th class="px-4 py-3 font-medium whitespace-nowrap" i18n="@@epssTrending.colSeverity">Severity</th>
                </tr>
              </thead>
              <tbody>
                @for (entry of entries(); track entry.vulnerability_id) {
                  <tr class="border-b border-slate-100 dark:border-slate-700/50 hover:bg-slate-50 dark:hover:bg-slate-700/30">
                    <td class="px-4 py-3">
                      <a [routerLink]="['/vulnerabilities', entry.vulnerability_id]"
                         class="text-indigo-600 dark:text-indigo-400 hover:underline font-mono text-xs">
                        {{ entry.cve_id || entry.vulnerability_id }}
                      </a>
                    </td>
                    <td class="px-4 py-3 font-mono text-xs text-slate-700 dark:text-slate-200">
                      {{ entry.current_epss * 100 | number:'1.2-2' }}%
                    </td>
                    <td class="px-4 py-3 font-mono text-xs text-slate-700 dark:text-slate-200">
                      {{ entry.previous_epss * 100 | number:'1.2-2' }}%
                    </td>
                    <td class="px-4 py-3">
                      <span class="font-mono text-xs font-semibold text-green-600 dark:text-green-400">
                        +{{ entry.delta * 100 | number:'1.2-2' }}%
                      </span>
                    </td>
                    <td class="px-4 py-3 font-mono text-xs text-slate-700 dark:text-slate-200">
                      {{ entry.current_percentile * 100 | number:'1.1-1' }}%
                    </td>
                    <td class="px-4 py-3">
                      <span [class]="severityBadgeClass(entry.severity)">{{ entry.severity || '-' }}</span>
                    </td>
                  </tr>
                }
              </tbody>
            </table>
          </div>
        </div>
      }

      <!-- Empty state -->
      @if (!loading() && entries().length === 0) {
        <div class="text-center py-12">
          <p class="text-slate-500 dark:text-slate-400" i18n="@@epssTrending.empty">No trending CVEs found for the selected criteria.</p>
        </div>
      }
    </div>
  `,
})
export class EpssTrendingComponent implements OnInit {
  private readonly trendingService = inject(EpssTrendingService);
  private readonly destroyRef = inject(DestroyRef);

  readonly loading = signal(true);
  readonly entries = signal<EpssTrendingEntry[]>([]);
  readonly latestDate = signal('');
  readonly previousDate = signal('');
  readonly stale = signal(false);
  readonly previousDateMissing = signal(false);
  readonly selectedDays = signal(7);
  readonly selectedThreshold = signal(0.1);

  readonly daysOptions = [
    { value: 7, label: $localize`:@@epssTrending.days7:7 Days` },
    { value: 14, label: $localize`:@@epssTrending.days14:14 Days` },
    { value: 30, label: $localize`:@@epssTrending.days30:30 Days` },
  ];

  readonly thresholdOptions = [
    { value: 0.01, label: '0.01' },
    { value: 0.05, label: '0.05' },
    { value: 0.1, label: '0.10' },
    { value: 0.2, label: '0.20' },
  ];

  ngOnInit(): void {
    this.loadData();
  }

  onDaysChange(days: number): void {
    this.selectedDays.set(days);
    this.loadData();
  }

  onThresholdChange(threshold: number): void {
    this.selectedThreshold.set(threshold);
    this.loadData();
  }

  severityBadgeClass(severity?: string): string {
    const base = 'inline-block px-1.5 py-0.5 rounded text-xs font-medium';
    switch (severity?.toUpperCase()) {
      case 'CRITICAL':
        return `${base} bg-red-100 text-red-700 dark:bg-red-900/30 dark:text-red-400`;
      case 'HIGH':
        return `${base} bg-orange-100 text-orange-700 dark:bg-orange-900/30 dark:text-orange-400`;
      case 'MEDIUM':
        return `${base} bg-yellow-100 text-yellow-700 dark:bg-yellow-900/30 dark:text-yellow-400`;
      case 'LOW':
        return `${base} bg-blue-100 text-blue-700 dark:bg-blue-900/30 dark:text-blue-400`;
      default:
        return `${base} bg-slate-100 text-slate-600 dark:bg-slate-700 dark:text-slate-300`;
    }
  }

  private loadData(): void {
    this.loading.set(true);
    this.trendingService
      .getTrending({
        days: this.selectedDays(),
        threshold: this.selectedThreshold(),
        limit: 50,
      })
      .pipe(takeUntilDestroyed(this.destroyRef))
      .subscribe({
        next: (res) => {
          this.entries.set(res.entries || []);
          this.latestDate.set(res.latest_date || '');
          this.previousDate.set(res.previous_date || '');
          this.stale.set(res.stale || false);
          this.previousDateMissing.set(res.previous_date_missing || false);
          this.loading.set(false);
        },
        error: () => {
          this.entries.set([]);
          this.latestDate.set('');
          this.previousDate.set('');
          this.stale.set(false);
          this.previousDateMissing.set(false);
          this.loading.set(false);
        },
      });
  }
}

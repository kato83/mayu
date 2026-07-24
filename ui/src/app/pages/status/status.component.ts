import { Component, inject, OnInit, signal } from '@angular/core';
import { DatePipe, DecimalPipe } from '@angular/common';

import { StatusService } from '../../services/status.service';
import { SyncState, EPSSCoverage } from '../../models/status.model';

@Component({
  selector: 'app-status',
  standalone: true,
  imports: [DatePipe, DecimalPipe],
  template: `
    <div class="space-y-6">
      <!-- Header -->
      <div class="flex items-center justify-between">
        <h1 class="text-2xl font-bold text-slate-900 dark:text-slate-100" i18n="@@status.title">Data Source Status</h1>
        <button
          (click)="loadStatus()"
          [disabled]="loading()"
          class="inline-flex items-center gap-2 rounded-md bg-indigo-600 px-3 py-2 text-sm font-medium text-white hover:bg-indigo-700 disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
        >
          <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15" />
          </svg>
          <span i18n="@@status.refresh">Refresh</span>
        </button>
      </div>

      <!-- Error -->
      @if (error()) {
        <div class="rounded-md border border-red-300 dark:border-red-700 bg-red-50 dark:bg-red-900/20 p-4 text-sm text-red-800 dark:text-red-300">
          {{ error() }}
        </div>
      }

      <!-- EPSS Coverage Card -->
      @if (epssCoverage()) {
        <div class="rounded-lg border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-800 shadow-sm p-5">
          <h2 class="text-lg font-semibold text-slate-900 dark:text-slate-100 mb-4" i18n="@@status.epssCoverage.title">EPSS Coverage</h2>
          <div class="grid grid-cols-2 md:grid-cols-4 gap-4">
            <div>
              <p class="text-xs text-slate-500 dark:text-slate-400 uppercase tracking-wider" i18n="@@status.epssCoverage.dateRange">Date Range</p>
              <p class="mt-1 text-sm font-medium text-slate-900 dark:text-slate-100">
                {{ epssCoverage()!.first_date }} — {{ epssCoverage()!.last_date }}
              </p>
            </div>
            <div>
              <p class="text-xs text-slate-500 dark:text-slate-400 uppercase tracking-wider" i18n="@@status.epssCoverage.daysCovered">Days Covered</p>
              <p class="mt-1 text-sm font-medium text-slate-900 dark:text-slate-100">
                {{ epssCoverage()!.total_days | number }}
              </p>
            </div>
            <div>
              <p class="text-xs text-slate-500 dark:text-slate-400 uppercase tracking-wider" i18n="@@status.epssCoverage.totalScores">Total Scores</p>
              <p class="mt-1 text-sm font-medium text-slate-900 dark:text-slate-100">
                {{ epssCoverage()!.total_scores | number }}
              </p>
            </div>
            <div>
              <p class="text-xs text-slate-500 dark:text-slate-400 uppercase tracking-wider" i18n="@@status.epssCoverage.coverage">Coverage</p>
              <p class="mt-1 text-sm font-medium text-slate-900 dark:text-slate-100">
                {{ coveragePercent() }}%
              </p>
            </div>
          </div>
          <!-- Coverage progress bar -->
          <div class="mt-4">
            <div class="w-full h-2 bg-slate-200 dark:bg-slate-700 rounded-full overflow-hidden">
              <div
                class="h-full bg-green-500 dark:bg-green-400 rounded-full transition-all"
                [style.width.%]="coveragePercent()"
              ></div>
            </div>
          </div>

          <!-- Missing dates -->
          @if (epssCoverage()!.missing_dates.length > 0) {
            <div class="mt-4">
              <button
                (click)="showMissingDates.set(!showMissingDates())"
                class="flex items-center gap-1 text-sm text-amber-700 dark:text-amber-400 hover:underline cursor-pointer"
              >
                <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-2.5L13.732 4c-.77-.833-1.964-.833-2.732 0L4.082 16.5c-.77.833.192 2.5 1.732 2.5z" />
                </svg>
                <span i18n="@@status.epssCoverage.missingDays">Missing days</span>: {{ epssCoverage()!.missing_dates.length }}
                <svg class="w-3 h-3 transition-transform" [class.rotate-180]="showMissingDates()" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 9l-7 7-7-7" />
                </svg>
              </button>
              @if (showMissingDates()) {
                <div class="mt-2 max-h-48 overflow-y-auto rounded border border-amber-200 dark:border-amber-800 bg-amber-50 dark:bg-amber-900/20 p-3">
                  <div class="grid grid-cols-3 sm:grid-cols-4 md:grid-cols-6 gap-1 text-xs font-mono text-amber-800 dark:text-amber-300">
                    @for (date of epssCoverage()!.missing_dates; track date) {
                      <span>{{ date }}</span>
                    }
                  </div>
                </div>
              }
            </div>
          }
        </div>
      }

      <!-- Sync States Table -->
      <div class="rounded-lg border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-800 shadow-sm overflow-hidden">
        <div class="overflow-x-auto">
          <table class="min-w-full divide-y divide-slate-200 dark:divide-slate-700">
            <thead class="bg-slate-50 dark:bg-slate-900/50">
              <tr>
                <th class="px-4 py-3 text-left text-xs font-medium text-slate-500 dark:text-slate-400 uppercase tracking-wider" i18n="@@status.col.sourceType">Type</th>
                <th class="px-4 py-3 text-left text-xs font-medium text-slate-500 dark:text-slate-400 uppercase tracking-wider" i18n="@@status.col.source">Source</th>
                <th class="px-4 py-3 text-left text-xs font-medium text-slate-500 dark:text-slate-400 uppercase tracking-wider" i18n="@@status.col.lastSynced">Last Synced</th>
                <th class="px-4 py-3 text-left text-xs font-medium text-slate-500 dark:text-slate-400 uppercase tracking-wider" i18n="@@status.col.lastModified">Last Modified</th>
                <th class="px-4 py-3 text-right text-xs font-medium text-slate-500 dark:text-slate-400 uppercase tracking-wider" i18n="@@status.col.recordCount">Records</th>
              </tr>
            </thead>
            <tbody class="divide-y divide-slate-200 dark:divide-slate-700">
              @if (loading() && syncStates().length === 0) {
                <tr>
                  <td colspan="5" class="px-4 py-8 text-center text-sm text-slate-500 dark:text-slate-400" i18n="@@status.loading">Loading...</td>
                </tr>
              } @else if (syncStates().length === 0) {
                <tr>
                  <td colspan="5" class="px-4 py-8 text-center text-sm text-slate-500 dark:text-slate-400" i18n="@@status.noData">No sync data found. Run an ingest operation to populate data.</td>
                </tr>
              } @else {
                @for (state of syncStates(); track state.source) {
                  <tr class="hover:bg-slate-50 dark:hover:bg-slate-700/50 transition-colors">
                    <td class="px-4 py-3">
                      <span [class]="sourceTypeBadgeClasses(state.source_type)">{{ state.source_type }}</span>
                    </td>
                    <td class="px-4 py-3 text-sm font-medium text-slate-900 dark:text-slate-100">{{ state.source }}</td>
                    <td class="px-4 py-3 text-sm text-slate-600 dark:text-slate-400">{{ state.last_synced_at | date:'yyyy-MM-dd HH:mm' }}</td>
                    <td class="px-4 py-3 text-sm text-slate-600 dark:text-slate-400">{{ state.last_modified_at | date:'yyyy-MM-dd HH:mm' }}</td>
                    <td class="px-4 py-3 text-sm text-right text-slate-700 dark:text-slate-300">{{ state.record_count | number }}</td>
                  </tr>
                }
              }
            </tbody>
          </table>
        </div>
      </div>
    </div>
  `,
})
export class StatusComponent implements OnInit {
  private readonly statusService = inject(StatusService);

  syncStates = signal<SyncState[]>([]);
  epssCoverage = signal<EPSSCoverage | null>(null);
  loading = signal(false);
  error = signal<string | null>(null);
  showMissingDates = signal(false);

  ngOnInit(): void {
    this.loadStatus();
  }

  loadStatus(): void {
    this.loading.set(true);
    this.error.set(null);

    this.statusService.getStatus().subscribe({
      next: (resp) => {
        this.syncStates.set(resp.sync_states ?? []);
        this.epssCoverage.set(resp.epss_coverage);
        this.loading.set(false);
      },
      error: (err) => {
        this.error.set(err?.error?.error ?? err?.message ?? 'Failed to load status');
        this.loading.set(false);
      },
    });
  }

  coveragePercent(): string {
    const coverage = this.epssCoverage();
    if (!coverage || !coverage.first_date || !coverage.last_date) {
      return '0';
    }
    const first = new Date(coverage.first_date);
    const last = new Date(coverage.last_date);
    const totalPossibleDays = Math.floor((last.getTime() - first.getTime()) / (1000 * 60 * 60 * 24)) + 1;
    if (totalPossibleDays <= 0) return '0';
    const percent = Math.min(100, (coverage.total_days / totalPossibleDays) * 100);
    return percent.toFixed(1);
  }

  sourceTypeBadgeClasses(sourceType: string): string {
    const base = 'inline-flex items-center rounded-full px-2.5 py-0.5 text-xs font-medium';
    switch (sourceType) {
      case 'osv':
        return `${base} bg-blue-100 text-blue-800 dark:bg-blue-900/30 dark:text-blue-300`;
      case 'nvd':
        return `${base} bg-purple-100 text-purple-800 dark:bg-purple-900/30 dark:text-purple-300`;
      case 'mitre':
        return `${base} bg-amber-100 text-amber-800 dark:bg-amber-900/30 dark:text-amber-300`;
      case 'epss':
        return `${base} bg-green-100 text-green-800 dark:bg-green-900/30 dark:text-green-300`;
      case 'kev':
        return `${base} bg-red-100 text-red-800 dark:bg-red-900/30 dark:text-red-300`;
      case 'ghsa':
        return `${base} bg-cyan-100 text-cyan-800 dark:bg-cyan-900/30 dark:text-cyan-300`;
      default:
        return `${base} bg-slate-100 text-slate-800 dark:bg-slate-700 dark:text-slate-300`;
    }
  }
}

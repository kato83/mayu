import { Component, inject, OnInit, signal } from '@angular/core';
import { DatePipe, JsonPipe } from '@angular/common';

import { IngestService } from '../../services/ingest.service';
import { IngestJob, IngestJobDetail } from '../../models/ingest.model';

@Component({
  selector: 'app-ingest-jobs',
  standalone: true,
  imports: [DatePipe, JsonPipe],
  template: `
    <div class="space-y-4">
      <!-- Header -->
      <div class="flex items-center justify-between">
        <h1 class="text-2xl font-bold text-slate-900 dark:text-slate-100" i18n="@@ingestJobs.title">Ingest Jobs</h1>
        <button
          (click)="loadJobs()"
          [disabled]="loading()"
          class="inline-flex items-center gap-2 rounded-md bg-indigo-600 px-3 py-2 text-sm font-medium text-white hover:bg-indigo-700 disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
        >
          <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15" />
          </svg>
          <span i18n="@@ingestJobs.refresh">Refresh</span>
        </button>
      </div>

      <!-- Error message -->
      @if (error()) {
        <div class="rounded-md border border-red-300 dark:border-red-700 bg-red-50 dark:bg-red-900/20 p-4 text-sm text-red-800 dark:text-red-300">
          {{ error() }}
        </div>
      }

      <!-- Jobs table -->
      <div class="rounded-lg border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-800 shadow-sm overflow-hidden">
        <div class="overflow-x-auto">
          <table class="min-w-full divide-y divide-slate-200 dark:divide-slate-700">
            <thead class="bg-slate-50 dark:bg-slate-900/50">
              <tr>
                <th class="px-4 py-3 text-left text-xs font-medium text-slate-500 dark:text-slate-400 uppercase tracking-wider" i18n="@@ingestJobs.col.id">ID</th>
                <th class="px-4 py-3 text-left text-xs font-medium text-slate-500 dark:text-slate-400 uppercase tracking-wider" i18n="@@ingestJobs.col.source">Source</th>
                <th class="px-4 py-3 text-left text-xs font-medium text-slate-500 dark:text-slate-400 uppercase tracking-wider" i18n="@@ingestJobs.col.status">Status</th>
                <th class="px-4 py-3 text-left text-xs font-medium text-slate-500 dark:text-slate-400 uppercase tracking-wider" i18n="@@ingestJobs.col.started">Started</th>
                <th class="px-4 py-3 text-left text-xs font-medium text-slate-500 dark:text-slate-400 uppercase tracking-wider" i18n="@@ingestJobs.col.duration">Duration</th>
                <th class="px-4 py-3 text-right text-xs font-medium text-slate-500 dark:text-slate-400 uppercase tracking-wider" i18n="@@ingestJobs.col.total">Total</th>
                <th class="px-4 py-3 text-right text-xs font-medium text-slate-500 dark:text-slate-400 uppercase tracking-wider" i18n="@@ingestJobs.col.success">Success</th>
                <th class="px-4 py-3 text-right text-xs font-medium text-slate-500 dark:text-slate-400 uppercase tracking-wider" i18n="@@ingestJobs.col.failed">Failed</th>
              </tr>
            </thead>
            <tbody class="divide-y divide-slate-200 dark:divide-slate-700">
              @if (loading() && jobs().length === 0) {
                <tr>
                  <td colspan="8" class="px-4 py-8 text-center text-sm text-slate-500 dark:text-slate-400" i18n="@@ingestJobs.loading">Loading...</td>
                </tr>
              } @else if (jobs().length === 0) {
                <tr>
                  <td colspan="8" class="px-4 py-8 text-center text-sm text-slate-500 dark:text-slate-400" i18n="@@ingestJobs.noJobs">No ingest jobs found.</td>
                </tr>
              } @else {
                @for (job of jobs(); track job.id) {
                  <tr
                    (click)="selectJob(job)"
                    class="cursor-pointer hover:bg-slate-50 dark:hover:bg-slate-700/50 transition-colors"
                    [class.bg-indigo-50]="selectedJob()?.id === job.id"
                    [class.dark:bg-indigo-900/20]="selectedJob()?.id === job.id"
                  >
                    <td class="px-4 py-3 text-sm font-mono text-slate-900 dark:text-slate-100">{{ job.id }}</td>
                    <td class="px-4 py-3 text-sm text-slate-700 dark:text-slate-300">{{ job.source }}</td>
                    <td class="px-4 py-3">
                      <span [class]="statusBadgeClasses(job.status)">{{ job.status }}</span>
                    </td>
                    <td class="px-4 py-3 text-sm text-slate-600 dark:text-slate-400">{{ job.started_at | date:'short' }}</td>
                    <td class="px-4 py-3 text-sm text-slate-600 dark:text-slate-400">{{ formatDuration(job) }}</td>
                    <td class="px-4 py-3 text-sm text-right text-slate-700 dark:text-slate-300">{{ job.total_count ?? '—' }}</td>
                    <td class="px-4 py-3 text-sm text-right text-green-700 dark:text-green-400">{{ job.success_count ?? '—' }}</td>
                    <td class="px-4 py-3 text-sm text-right text-red-700 dark:text-red-400">{{ job.failure_count ?? '—' }}</td>
                  </tr>
                }
              }
            </tbody>
          </table>
        </div>
      </div>

      <!-- Detail panel -->
      @if (jobDetail()) {
        <div class="rounded-lg border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-800 shadow-sm p-4 space-y-4">
          <div class="flex items-center justify-between">
            <h2 class="text-lg font-semibold text-slate-900 dark:text-slate-100" i18n="@@ingestJobs.detail.title">
              Job Detail
            </h2>
            <button
              (click)="closeDetail()"
              class="text-slate-400 hover:text-slate-600 dark:hover:text-slate-200 transition-colors"
              aria-label="Close detail"
              i18n-aria-label="@@ingestJobs.detail.close"
            >
              <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12" />
              </svg>
            </button>
          </div>

          <!-- Command args -->
          <div>
            <h3 class="text-sm font-medium text-slate-600 dark:text-slate-400 mb-1" i18n="@@ingestJobs.detail.commandArgs">Command Arguments</h3>
            <pre class="rounded-md bg-slate-100 dark:bg-slate-900 p-3 text-xs font-mono text-slate-800 dark:text-slate-200 overflow-x-auto">{{ jobDetail()!.command_args | json }}</pre>
          </div>

          <!-- Error message -->
          @if (jobDetail()!.error_message) {
            <div>
              <h3 class="text-sm font-medium text-red-600 dark:text-red-400 mb-1" i18n="@@ingestJobs.detail.error">Error</h3>
              <pre class="rounded-md bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800 p-3 text-xs font-mono text-red-800 dark:text-red-300 overflow-x-auto whitespace-pre-wrap">{{ jobDetail()!.error_message }}</pre>
            </div>
          }

          <!-- Failures table -->
          @if (jobDetail()!.failures && jobDetail()!.failures.length > 0) {
            <div>
              <h3 class="text-sm font-medium text-slate-600 dark:text-slate-400 mb-2" i18n="@@ingestJobs.detail.failures">
                Failures ({{ jobDetail()!.failures.length }})
              </h3>
              <div class="overflow-x-auto rounded-md border border-slate-200 dark:border-slate-700">
                <table class="min-w-full divide-y divide-slate-200 dark:divide-slate-700">
                  <thead class="bg-slate-50 dark:bg-slate-900/50">
                    <tr>
                      <th class="px-3 py-2 text-left text-xs font-medium text-slate-500 dark:text-slate-400 uppercase" i18n="@@ingestJobs.detail.col.vulnId">Vuln ID</th>
                      <th class="px-3 py-2 text-left text-xs font-medium text-slate-500 dark:text-slate-400 uppercase" i18n="@@ingestJobs.detail.col.errorType">Error Type</th>
                      <th class="px-3 py-2 text-left text-xs font-medium text-slate-500 dark:text-slate-400 uppercase" i18n="@@ingestJobs.detail.col.message">Message</th>
                      <th class="px-3 py-2 text-left text-xs font-medium text-slate-500 dark:text-slate-400 uppercase" i18n="@@ingestJobs.detail.col.time">Time</th>
                    </tr>
                  </thead>
                  <tbody class="divide-y divide-slate-200 dark:divide-slate-700">
                    @for (failure of jobDetail()!.failures; track failure.id) {
                      <tr class="hover:bg-slate-50 dark:hover:bg-slate-700/50">
                        <td class="px-3 py-2 text-xs font-mono text-slate-900 dark:text-slate-100">{{ failure.vuln_id }}</td>
                        <td class="px-3 py-2 text-xs text-slate-600 dark:text-slate-400">{{ failure.error_type }}</td>
                        <td class="px-3 py-2 text-xs text-slate-600 dark:text-slate-400 max-w-xs truncate" [title]="failure.error_message ?? ''">{{ failure.error_message ?? '—' }}</td>
                        <td class="px-3 py-2 text-xs text-slate-500 dark:text-slate-400">{{ failure.failed_at | date:'short' }}</td>
                      </tr>
                    }
                  </tbody>
                </table>
              </div>
            </div>
          }
        </div>
      }

      <!-- Detail loading -->
      @if (detailLoading()) {
        <div class="rounded-lg border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-800 shadow-sm p-8 text-center text-sm text-slate-500 dark:text-slate-400" i18n="@@ingestJobs.detail.loading">
          Loading job details...
        </div>
      }
    </div>
  `,
})
export class IngestJobsComponent implements OnInit {
  private readonly ingestService = inject(IngestService);

  readonly jobs = signal<IngestJob[]>([]);
  readonly loading = signal(false);
  readonly error = signal<string | null>(null);
  readonly selectedJob = signal<IngestJob | null>(null);
  readonly jobDetail = signal<IngestJobDetail | null>(null);
  readonly detailLoading = signal(false);

  ngOnInit(): void {
    this.loadJobs();
  }

  loadJobs(): void {
    this.loading.set(true);
    this.error.set(null);
    this.ingestService.listJobs(50).subscribe({
      next: (response) => {
        this.jobs.set(response.jobs ?? []);
        this.loading.set(false);
      },
      error: (err) => {
        this.error.set(err?.message ?? 'Failed to load ingest jobs');
        this.loading.set(false);
      },
    });
  }

  selectJob(job: IngestJob): void {
    if (this.selectedJob()?.id === job.id) {
      this.closeDetail();
      return;
    }
    this.selectedJob.set(job);
    this.jobDetail.set(null);
    this.detailLoading.set(true);
    this.ingestService.getJob(job.id).subscribe({
      next: (detail) => {
        this.jobDetail.set(detail);
        this.detailLoading.set(false);
      },
      error: (err) => {
        this.error.set(err?.message ?? 'Failed to load job detail');
        this.detailLoading.set(false);
      },
    });
  }

  closeDetail(): void {
    this.selectedJob.set(null);
    this.jobDetail.set(null);
  }

  formatDuration(job: IngestJob): string {
    if (!job.finished_at) {
      if (job.status === 'running') {
        return '⏳';
      }
      return '—';
    }
    const start = new Date(job.started_at).getTime();
    const end = new Date(job.finished_at).getTime();
    const diffMs = end - start;
    if (diffMs < 1000) {
      return `${diffMs}ms`;
    }
    const seconds = Math.floor(diffMs / 1000);
    if (seconds < 60) {
      return `${seconds}s`;
    }
    const minutes = Math.floor(seconds / 60);
    const remainingSec = seconds % 60;
    if (minutes < 60) {
      return `${minutes}m ${remainingSec}s`;
    }
    const hours = Math.floor(minutes / 60);
    const remainingMin = minutes % 60;
    return `${hours}h ${remainingMin}m`;
  }

  statusBadgeClasses(status: string): string {
    const base = 'inline-flex items-center rounded-full px-2 py-0.5 text-xs font-medium';
    switch (status) {
      case 'success':
        return `${base} bg-green-100 text-green-800 dark:bg-green-900/30 dark:text-green-400`;
      case 'failed':
        return `${base} bg-red-100 text-red-800 dark:bg-red-900/30 dark:text-red-400`;
      case 'partial':
        return `${base} bg-yellow-100 text-yellow-800 dark:bg-yellow-900/30 dark:text-yellow-400`;
      case 'running':
        return `${base} bg-blue-100 text-blue-800 dark:bg-blue-900/30 dark:text-blue-400`;
      default:
        return `${base} bg-slate-100 text-slate-800 dark:bg-slate-700 dark:text-slate-300`;
    }
  }
}

import { Component, inject, signal, OnInit, OnDestroy, DestroyRef, computed } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { DecimalPipe } from '@angular/common';
import { takeUntilDestroyed } from '@angular/core/rxjs-interop';
import { Subscription } from 'rxjs';

import { IngestService } from '../../services/ingest.service';
import { VulnerabilityService } from '../../services/vulnerability.service';
import { IngestType, IngestEvent } from '../../models/ingest.model';

interface IngestOption {
  value: IngestType;
  label: string;
  needsEcosystem: boolean;
  needsRepo: boolean;
  needsDates: boolean;
}

@Component({
  selector: 'app-ingest',
  standalone: true,
  imports: [FormsModule, DecimalPipe],
  template: `
    <div class="space-y-6">
      <!-- Header -->
      <div>
        <h1 class="text-2xl font-bold text-slate-900 dark:text-slate-100" i18n="@@ingest.title">Data Ingest</h1>
        <p class="mt-1 text-sm text-slate-600 dark:text-slate-400" i18n="@@ingest.description">
          Import vulnerability data from various sources into the local database.
        </p>
      </div>

      <!-- Configuration panel -->
      <div class="rounded-lg border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-800 p-6 shadow-sm">
        <div class="space-y-4">
          <!-- Ingest type selection -->
          <div>
            <label for="ingest-type" class="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-1" i18n="@@ingest.typeLabel">
              Ingest Type
            </label>
            <select
              id="ingest-type"
              [(ngModel)]="selectedType"
              [disabled]="running()"
              class="w-full max-w-md rounded-md border border-slate-300 dark:border-slate-600 dark:bg-slate-700 dark:text-slate-200 px-3 py-2 text-sm focus:border-indigo-500 focus:ring-1 focus:ring-indigo-500 outline-none disabled:opacity-50"
            >
              @for (opt of ingestOptions; track opt.value) {
                <option [value]="opt.value">{{ opt.label }}</option>
              }
            </select>
          </div>

          <!-- Ecosystem selection (conditional) -->
          @if (selectedOption()?.needsEcosystem) {
            <div>
              <label for="ecosystem-select" class="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-1" i18n="@@ingest.ecosystemLabel">
                Ecosystem
              </label>
              @if (ecosystemsLoading()) {
                <p class="text-sm text-slate-500 dark:text-slate-400" i18n="@@ingest.ecosystemLoading">Loading ecosystems...</p>
              } @else {
                <select
                  id="ecosystem-select"
                  [(ngModel)]="selectedEcosystem"
                  [disabled]="running()"
                  class="w-full max-w-md rounded-md border border-slate-300 dark:border-slate-600 dark:bg-slate-700 dark:text-slate-200 px-3 py-2 text-sm focus:border-indigo-500 focus:ring-1 focus:ring-indigo-500 outline-none disabled:opacity-50"
                >
                  <option value="" i18n="@@ingest.ecosystemPlaceholder">-- Select Ecosystem --</option>
                  @for (eco of ecosystems(); track eco) {
                    <option [value]="eco">{{ eco }}</option>
                  }
                </select>
              }
            </div>
          }

          <!-- Repository input (for GHSA) -->
          @if (selectedOption()?.needsRepo) {
            <div>
              <label for="repo-input" class="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-1" i18n="@@ingest.repoLabel">
                Repository (owner/repo)
              </label>
              <input
                id="repo-input"
                type="text"
                [(ngModel)]="repoInput"
                [disabled]="running()"
                placeholder="e.g. WordPress/wordpress-develop"
                i18n-placeholder="@@ingest.repoPlaceholder"
                class="w-full max-w-md rounded-md border border-slate-300 dark:border-slate-600 dark:bg-slate-700 dark:text-slate-200 px-3 py-2 text-sm focus:border-indigo-500 focus:ring-1 focus:ring-indigo-500 outline-none disabled:opacity-50"
              />
            </div>
          }

          <!-- Date range inputs (for EPSS Backfill) -->
          @if (selectedOption()?.needsDates) {
            <div class="flex flex-wrap gap-4">
              <div>
                <label for="from-date" class="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-1" i18n="@@ingest.fromLabel">
                  From (YYYY-MM-DD)
                </label>
                <input
                  id="from-date"
                  type="date"
                  [(ngModel)]="fromDate"
                  [disabled]="running()"
                  class="rounded-md border border-slate-300 dark:border-slate-600 dark:bg-slate-700 dark:text-slate-200 px-3 py-2 text-sm focus:border-indigo-500 focus:ring-1 focus:ring-indigo-500 outline-none disabled:opacity-50"
                />
              </div>
              <div>
                <label for="to-date" class="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-1" i18n="@@ingest.toLabel">
                  To (YYYY-MM-DD)
                </label>
                <input
                  id="to-date"
                  type="date"
                  [(ngModel)]="toDate"
                  [disabled]="running()"
                  class="rounded-md border border-slate-300 dark:border-slate-600 dark:bg-slate-700 dark:text-slate-200 px-3 py-2 text-sm focus:border-indigo-500 focus:ring-1 focus:ring-indigo-500 outline-none disabled:opacity-50"
                />
              </div>
            </div>
            <p class="text-xs text-slate-500 dark:text-slate-400" i18n="@@ingest.datesHint">
              Leave empty to use defaults (2023-03-07 to today).
            </p>
          }

          <!-- Start button -->
          <div>
            <button
              (click)="startIngest()"
              [disabled]="!canStart()"
              class="inline-flex items-center gap-2 rounded-md bg-indigo-600 px-4 py-2 text-sm font-medium text-white hover:bg-indigo-700 focus:outline-none focus:ring-2 focus:ring-indigo-500 focus:ring-offset-2 disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
            >
              @if (running()) {
                <svg class="animate-spin h-4 w-4" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24">
                  <circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="4"></circle>
                  <path class="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
                </svg>
                <span i18n="@@ingest.running">Running...</span>
              } @else {
                <span i18n="@@ingest.startButton">Start Ingest</span>
              }
            </button>
          </div>
        </div>
      </div>

      <!-- Progress section -->
      @if (events().length > 0) {
        <div class="rounded-lg border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-800 p-6 shadow-sm space-y-4">
          <h2 class="text-lg font-semibold text-slate-900 dark:text-slate-100" i18n="@@ingest.progressTitle">Progress</h2>

          <!-- Progress bar -->
          @if (progressPercent() !== null) {
            <div class="w-full bg-slate-200 dark:bg-slate-700 rounded-full h-3">
              <div
                class="h-3 rounded-full transition-all duration-300"
                [class]="progressBarClasses()"
                [style.width.%]="progressPercent()"
              ></div>
            </div>
            <p class="text-sm text-slate-600 dark:text-slate-400">
              {{ latestEvent()?.current ?? 0 }} / {{ latestEvent()?.total ?? 0 }}
              ({{ progressPercent() | number:'1.0-1' }}%)
            </p>
          }

          <!-- Status indicator -->
          @if (status() === 'done') {
            <div class="flex items-center gap-2 text-green-700 dark:text-green-400">
              <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 13l4 4L19 7" />
              </svg>
              <span class="text-sm font-medium" i18n="@@ingest.statusDone">Ingest completed successfully.</span>
            </div>
          }
          @if (status() === 'error') {
            <div class="flex items-center gap-2 text-red-700 dark:text-red-400">
              <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12" />
              </svg>
              <span class="text-sm font-medium" i18n="@@ingest.statusError">Ingest failed.</span>
            </div>
          }

          <!-- Log output -->
          <div>
            <h3 class="text-sm font-medium text-slate-700 dark:text-slate-300 mb-2" i18n="@@ingest.logTitle">Event Log</h3>
            <div class="max-h-64 overflow-y-auto rounded-md bg-slate-50 dark:bg-slate-900 border border-slate-200 dark:border-slate-700 p-3 font-mono text-xs text-slate-700 dark:text-slate-300 space-y-1">
              @for (event of events(); track $index) {
                <div [class]="eventLogClasses(event)">
                  <span class="font-semibold">[{{ event.phase }}]</span>
                  @if (event.message) {
                    <span> {{ event.message }}</span>
                  }
                  @if (event.current != null && event.total != null) {
                    <span class="text-slate-500 dark:text-slate-400"> ({{ event.current }}/{{ event.total }})</span>
                  }
                </div>
              }
            </div>
          </div>
        </div>
      }
    </div>
  `,
})
export class IngestComponent implements OnInit, OnDestroy {
  private readonly ingestService = inject(IngestService);
  private readonly vulnerabilityService = inject(VulnerabilityService);
  private readonly destroyRef = inject(DestroyRef);

  private streamSub: Subscription | null = null;

  readonly ingestOptions: IngestOption[] = [
    { value: 'ecosystem', label: $localize`:@@ingest.option.ecosystem:Ecosystem (Full)`, needsEcosystem: true, needsRepo: false, needsDates: false },
    { value: 'ecosystem_update', label: $localize`:@@ingest.option.ecosystemUpdate:Ecosystem (Delta Update)`, needsEcosystem: true, needsRepo: false, needsDates: false },
    { value: 'all', label: $localize`:@@ingest.option.all:All Ecosystems`, needsEcosystem: false, needsRepo: false, needsDates: false },
    { value: 'all_bulk', label: $localize`:@@ingest.option.allBulk:All Ecosystems (Bulk)`, needsEcosystem: false, needsRepo: false, needsDates: false },
    { value: 'nvd', label: $localize`:@@ingest.option.nvd:NVD`, needsEcosystem: false, needsRepo: false, needsDates: false },
    { value: 'nvd_update', label: $localize`:@@ingest.option.nvdUpdate:NVD (Delta Update)`, needsEcosystem: false, needsRepo: false, needsDates: false },
    { value: 'nvd_converted', label: $localize`:@@ingest.option.nvdConverted:NVD (Converted)`, needsEcosystem: false, needsRepo: false, needsDates: false },
    { value: 'mitre', label: $localize`:@@ingest.option.mitre:MITRE`, needsEcosystem: false, needsRepo: false, needsDates: false },
    { value: 'mitre_update', label: $localize`:@@ingest.option.mitreUpdate:MITRE (Delta Update)`, needsEcosystem: false, needsRepo: false, needsDates: false },
    { value: 'epss', label: $localize`:@@ingest.option.epss:EPSS`, needsEcosystem: false, needsRepo: false, needsDates: false },
    { value: 'epss_update', label: $localize`:@@ingest.option.epssUpdate:EPSS (Delta Update)`, needsEcosystem: false, needsRepo: false, needsDates: false },
    { value: 'epss_backfill', label: $localize`:@@ingest.option.epssBackfill:EPSS (Backfill)`, needsEcosystem: false, needsRepo: false, needsDates: true },
    { value: 'kev', label: $localize`:@@ingest.option.kev:KEV`, needsEcosystem: false, needsRepo: false, needsDates: false },
    { value: 'kev_update', label: $localize`:@@ingest.option.kevUpdate:KEV (Delta Update)`, needsEcosystem: false, needsRepo: false, needsDates: false },
    { value: 'debian', label: $localize`:@@ingest.option.debian:Debian`, needsEcosystem: false, needsRepo: false, needsDates: false },
    { value: 'ghsa', label: $localize`:@@ingest.option.ghsa:GitHub Security Advisories`, needsEcosystem: false, needsRepo: true, needsDates: false },
  ];

  selectedType: IngestType = 'ecosystem';
  selectedEcosystem = '';
  repoInput = '';
  fromDate = '';
  toDate = '';

  readonly running = signal(false);
  readonly status = signal<'idle' | 'running' | 'done' | 'error'>('idle');
  readonly events = signal<IngestEvent[]>([]);
  readonly ecosystems = signal<string[]>([]);
  readonly ecosystemsLoading = signal(false);
  readonly activeJobId = signal<number | null>(null);

  constructor() {
    this.loadEcosystems();
  }

  ngOnInit(): void {
    // Check if there's a running job and reconnect to its progress stream.
    this.checkRunningJob();
  }

  ngOnDestroy(): void {
    this.streamSub?.unsubscribe();
  }

  selectedOption(): IngestOption | undefined {
    return this.ingestOptions.find((o) => o.value === this.selectedType);
  }

  canStart(): boolean {
    if (this.running()) return false;
    const opt = this.selectedOption();
    if (!opt) return false;
    if (opt.needsEcosystem && !this.selectedEcosystem) return false;
    if (opt.needsRepo && !this.repoInput.includes('/')) return false;
    return true;
  }

  latestEvent(): IngestEvent | null {
    const evts = this.events();
    return evts.length > 0 ? evts[evts.length - 1] : null;
  }

  progressPercent(): number | null {
    const evt = this.latestEvent();
    if (evt?.current != null && evt?.total != null && evt.total > 0) {
      return (evt.current / evt.total) * 100;
    }
    return null;
  }

  progressBarClasses(): string {
    switch (this.status()) {
      case 'done':
        return 'bg-green-500';
      case 'error':
        return 'bg-red-500';
      default:
        return 'bg-indigo-500';
    }
  }

  eventLogClasses(event: IngestEvent): string {
    switch (event.phase) {
      case 'error':
        return 'text-red-600 dark:text-red-400';
      case 'done':
        return 'text-green-600 dark:text-green-400';
      case 'summary':
        return 'text-indigo-600 dark:text-indigo-400';
      default:
        return '';
    }
  }

  startIngest(): void {
    if (!this.canStart()) return;

    this.running.set(true);
    this.status.set('running');
    this.events.set([]);

    const params = {
      type: this.selectedType,
      ...(this.selectedOption()?.needsEcosystem ? { ecosystem: this.selectedEcosystem } : {}),
      ...(this.selectedOption()?.needsRepo ? { repo: this.repoInput.trim() } : {}),
      ...(this.selectedOption()?.needsDates && this.fromDate ? { from: this.fromDate } : {}),
      ...(this.selectedOption()?.needsDates && this.toDate ? { to: this.toDate } : {}),
    };

    this.ingestService
      .startIngest(params)
      .pipe(takeUntilDestroyed(this.destroyRef))
      .subscribe({
        next: (resp) => {
          this.activeJobId.set(resp.job_id);
          this.subscribeToStream(resp.job_id);
        },
        error: (err) => {
          const msg = err?.error?.error ?? err?.message ?? 'Failed to start ingest';
          this.events.update((prev) => [
            ...prev,
            { phase: 'error' as const, message: msg },
          ]);
          this.status.set('error');
          this.running.set(false);
        },
      });
  }

  private subscribeToStream(jobId: number): void {
    this.streamSub?.unsubscribe();

    this.streamSub = this.ingestService
      .streamProgress(jobId)
      .pipe(takeUntilDestroyed(this.destroyRef))
      .subscribe({
        next: (event) => {
          this.events.update((prev) => [...prev, event]);
          if (event.phase === 'done') {
            this.status.set('done');
            this.running.set(false);
            this.activeJobId.set(null);
          } else if (event.phase === 'error') {
            this.status.set('error');
            this.running.set(false);
            this.activeJobId.set(null);
          }
        },
        error: (err) => {
          this.events.update((prev) => [
            ...prev,
            { phase: 'error' as const, message: err?.message ?? 'Stream connection lost' },
          ]);
          this.status.set('error');
          this.running.set(false);
          this.activeJobId.set(null);
        },
        complete: () => {
          if (this.status() === 'running') {
            this.status.set('done');
            this.running.set(false);
            this.activeJobId.set(null);
          }
        },
      });
  }

  /**
   * On init, check if there's a running ingest job.
   * If so, reconnect to its progress stream.
   */
  private checkRunningJob(): void {
    this.ingestService
      .listJobs(1)
      .pipe(takeUntilDestroyed(this.destroyRef))
      .subscribe({
        next: (resp) => {
          const runningJob = resp.jobs.find((j) => j.status === 'running');
          if (runningJob) {
            this.running.set(true);
            this.status.set('running');
            this.activeJobId.set(runningJob.id);
            this.subscribeToStream(runningJob.id);
          }
        },
      });
  }

  private loadEcosystems(): void {
    this.ecosystemsLoading.set(true);
    this.vulnerabilityService
      .getEcosystems()
      .pipe(takeUntilDestroyed(this.destroyRef))
      .subscribe({
        next: (res) => {
          this.ecosystems.set(res.ecosystems);
          this.ecosystemsLoading.set(false);
        },
        error: () => {
          this.ecosystemsLoading.set(false);
        },
      });
  }
}

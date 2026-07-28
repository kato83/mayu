import { Component, ElementRef, ViewChild, inject, signal, OnInit, OnDestroy, effect } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { DatePipe } from '@angular/common';
import { ActivatedRoute, RouterLink } from '@angular/router';
import { Chart, registerables } from 'chart.js';

import { SbomService } from '../../services/sbom.service';
import { StatsTrendService } from '../../services/stats-trend.service';
import { ThemeService } from '../../services/theme.service';
import { SBOMProject, SBOMVersion, SBOMScanResult } from '../../models/sbom.model';
import { StatsTrendResponse } from '../../models/stats-trend.model';

Chart.register(...registerables);

@Component({
  selector: 'app-sbom-project-detail',
  standalone: true,
  imports: [FormsModule, DatePipe, RouterLink],
  template: `
    <div class="p-6">
      <!-- Header -->
      <div class="flex items-center gap-4 mb-6">
        <a routerLink="/sbom" class="text-blue-600 hover:text-blue-800 dark:text-blue-400 dark:hover:text-blue-300" i18n="@@sbom.detail.backToProjects">
          &larr; Back to Projects
        </a>
      </div>

      @if (project()) {
        <h1 class="text-2xl font-bold text-slate-900 dark:text-white mb-6">{{ project()!.name }}</h1>
      }

      <!-- Project Vulnerability Trend chart -->
      @if (trendData() && trendData()!.data_points.length > 0) {
        <section class="bg-white dark:bg-slate-800 rounded-lg shadow p-4 mb-6">
          <div class="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-2 mb-3">
            <h2 class="text-sm font-semibold text-slate-700 dark:text-slate-200" i18n="@@sbom.detail.trendTitle">Vulnerability Trend</h2>
            <div class="flex gap-1">
              @for (r of trendRanges; track r.value) {
                <button
                  (click)="onProjectTrendRangeChange(r.value)"
                  [class]="selectedProjectTrendRange() === r.value ? 'px-2 py-1 text-xs font-medium rounded bg-indigo-600 text-white cursor-pointer' : 'px-2 py-1 text-xs font-medium rounded bg-slate-100 dark:bg-slate-700 text-slate-600 dark:text-slate-300 hover:bg-slate-200 dark:hover:bg-slate-600 cursor-pointer'"
                >{{ r.label }}</button>
              }
            </div>
          </div>
          <div class="relative w-full" style="height: 240px">
            <canvas #projectTrendCanvas></canvas>
          </div>
        </section>
      }

      <!-- Upload SBOM form -->
      <div class="mb-8">
        <button
          (click)="showUploadForm.set(!showUploadForm())"
          class="px-4 py-2 bg-blue-600 hover:bg-blue-700 text-white font-medium rounded-md transition-colors cursor-pointer"
          i18n="@@sbom.detail.uploadButton"
        >
          Upload SBOM
        </button>

        @if (showUploadForm()) {
          <div class="mt-4 p-4 bg-slate-50 dark:bg-slate-800 border border-slate-200 dark:border-slate-700 rounded-lg">
            <h2 class="text-lg font-semibold text-slate-900 dark:text-white mb-4" i18n="@@sbom.detail.uploadTitle">
              Upload SBOM File
            </h2>
            <form #uploadForm="ngForm" (ngSubmit)="onUpload()" class="space-y-4">
              <div>
                <label for="sbomVersion" class="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-1" i18n="@@sbom.detail.versionLabel">
                  Version
                </label>
                <input
                  id="sbomVersion"
                  type="text"
                  [(ngModel)]="uploadVersion"
                  name="sbomVersion"
                  required
                  #versionCtrl="ngModel"
                  class="w-full px-3 py-2 border rounded-md bg-white dark:bg-slate-700 text-slate-900 dark:text-white placeholder-slate-400 focus:outline-none focus:ring-2 focus:ring-blue-500"
                  [class]="versionCtrl.invalid && (versionCtrl.dirty || versionCtrl.touched) ? 'border-red-500 dark:border-red-500' : 'border-slate-300 dark:border-slate-600'"
                  placeholder="e.g. 1.0.0"
                  i18n-placeholder="@@sbom.detail.versionPlaceholder"
                />
              </div>
              <div>
                <label for="sbomEnv" class="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-1" i18n="@@sbom.detail.environmentLabel">
                  Environment
                </label>
                <input
                  id="sbomEnv"
                  type="text"
                  [(ngModel)]="uploadEnvironment"
                  name="sbomEnv"
                  class="w-full px-3 py-2 border border-slate-300 dark:border-slate-600 rounded-md bg-white dark:bg-slate-700 text-slate-900 dark:text-white placeholder-slate-400 focus:outline-none focus:ring-2 focus:ring-blue-500"
                  placeholder="e.g. production"
                  i18n-placeholder="@@sbom.detail.environmentPlaceholder"
                />
              </div>
              <div>
                <label for="sbomFile" class="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-1" i18n="@@sbom.detail.fileLabel">
                  SBOM File (JSON)
                </label>
                <input
                  id="sbomFile"
                  type="file"
                  (change)="onFileSelected($event)"
                  accept=".json"
                  class="w-full px-3 py-2 border border-slate-300 dark:border-slate-600 rounded-md bg-white dark:bg-slate-700 text-slate-900 dark:text-white focus:outline-none focus:ring-2 focus:ring-blue-500"
                />
              </div>
              <div class="flex gap-2">
                <button
                  type="submit"
                  [disabled]="uploading() || uploadForm.invalid || !selectedFile()"
                  class="px-4 py-2 bg-blue-600 hover:bg-blue-700 disabled:bg-blue-400 text-white font-medium rounded-md transition-colors cursor-pointer disabled:cursor-not-allowed"
                  i18n="@@sbom.detail.uploadSubmitButton"
                >
                  Upload
                </button>
                <button
                  type="button"
                  (click)="showUploadForm.set(false)"
                  class="px-4 py-2 bg-slate-200 dark:bg-slate-700 hover:bg-slate-300 dark:hover:bg-slate-600 text-slate-700 dark:text-slate-300 font-medium rounded-md transition-colors cursor-pointer"
                  i18n="@@sbom.detail.cancelButton"
                >
                  Cancel
                </button>
              </div>
            </form>
            @if (uploadError()) {
              <p class="mt-2 text-sm text-red-600 dark:text-red-400">{{ uploadError() }}</p>
            }
          </div>
        }
      </div>

      <!-- Versions list -->
      <h2 class="text-xl font-semibold text-slate-900 dark:text-white mb-4" i18n="@@sbom.detail.versionsTitle">
        Versions
      </h2>

      @if (versionsLoading()) {
        <p class="text-slate-500 dark:text-slate-400" i18n="@@sbom.detail.loading">Loading...</p>
      } @else if (versions().length === 0) {
        <p class="text-slate-500 dark:text-slate-400" i18n="@@sbom.detail.noVersions">
          No versions uploaded yet. Upload an SBOM to get started.
        </p>
      } @else {
        <div class="overflow-x-auto mb-8">
          <table class="w-full text-sm text-left">
            <thead class="text-xs uppercase bg-slate-50 dark:bg-slate-800 text-slate-600 dark:text-slate-400">
              <tr>
                <th class="px-4 py-3 whitespace-nowrap" i18n="@@sbom.detail.col.version">Version</th>
                <th class="px-4 py-3 whitespace-nowrap" i18n="@@sbom.detail.col.format">Format</th>
                <th class="px-4 py-3 whitespace-nowrap" i18n="@@sbom.detail.col.components">Components</th>
                <th class="px-4 py-3 whitespace-nowrap" i18n="@@sbom.detail.col.environment">Environment</th>
                <th class="px-4 py-3 whitespace-nowrap" i18n="@@sbom.detail.col.created">Created</th>
                <th class="px-4 py-3 whitespace-nowrap" i18n="@@sbom.detail.col.actions">Actions</th>
              </tr>
            </thead>
            <tbody>
              @for (ver of versions(); track ver.id) {
                <tr class="border-b border-slate-200 dark:border-slate-700">
                  <td class="px-4 py-3 text-slate-900 dark:text-white font-medium">{{ ver.version }}</td>
                  <td class="px-4 py-3 text-slate-600 dark:text-slate-400">
                    <span class="px-2 py-0.5 rounded text-xs font-medium bg-slate-200 dark:bg-slate-700 text-slate-700 dark:text-slate-300">
                      {{ ver.sbom_format || '-' }}
                    </span>
                  </td>
                  <td class="px-4 py-3 text-slate-600 dark:text-slate-400">{{ ver.component_count }}</td>
                  <td class="px-4 py-3 text-slate-600 dark:text-slate-400">{{ ver.environment || '-' }}</td>
                  <td class="px-4 py-3 text-slate-600 dark:text-slate-400">{{ ver.created_at | date:'short' }}</td>
                  <td class="px-4 py-3">
                    <button
                      (click)="onViewScans(ver)"
                      class="text-blue-600 hover:text-blue-800 dark:text-blue-400 dark:hover:text-blue-300 font-medium cursor-pointer"
                      i18n="@@sbom.detail.viewScansButton"
                    >
                      Scans
                    </button>
                  </td>
                </tr>
              }
            </tbody>
          </table>
        </div>
      }

      <!-- Scan results for selected version -->
      @if (selectedVersion()) {
        <div class="mt-6">
          <div class="flex items-center justify-between mb-4">
            <h2 class="text-lg font-semibold text-slate-900 dark:text-white">
              <span i18n="@@sbom.detail.scanResultsFor">Scan Results for</span> {{ selectedVersion()!.version }}
            </h2>
            <button
              (click)="selectedVersion.set(null)"
              class="text-sm text-slate-500 hover:text-slate-700 dark:text-slate-400 dark:hover:text-slate-200 cursor-pointer"
              i18n="@@sbom.detail.closeScans"
            >
              Close
            </button>
          </div>

          @if (scansLoading()) {
            <p class="text-slate-500 dark:text-slate-400" i18n="@@sbom.detail.loading">Loading...</p>
          } @else if (scanResults().length === 0) {
            <p class="text-slate-500 dark:text-slate-400" i18n="@@sbom.detail.noScans">
              No scan results available for this version.
            </p>
          } @else {
            <div class="overflow-x-auto">
              <table class="w-full text-sm text-left">
                <thead class="text-xs uppercase bg-slate-50 dark:bg-slate-800 text-slate-600 dark:text-slate-400">
                  <tr>
                    <th class="px-4 py-3 whitespace-nowrap" i18n="@@sbom.detail.col.scannedAt">Scanned At</th>
                    <th class="px-4 py-3 whitespace-nowrap" i18n="@@sbom.detail.col.status">Status</th>
                    <th class="px-4 py-3 whitespace-nowrap" i18n="@@sbom.detail.col.findings">Findings</th>
                    <th class="px-4 py-3 whitespace-nowrap" i18n="@@sbom.detail.col.new">New</th>
                    <th class="px-4 py-3 whitespace-nowrap" i18n="@@sbom.detail.col.resolved">Resolved</th>
                    <th class="px-4 py-3 whitespace-nowrap" i18n="@@sbom.detail.col.trigger">Trigger</th>
                    <th class="px-4 py-3 whitespace-nowrap" i18n="@@sbom.detail.col.actions">Actions</th>
                  </tr>
                </thead>
                <tbody>
                  @for (scan of scanResults(); track scan.id) {
                    <tr class="border-b border-slate-200 dark:border-slate-700">
                      <td class="px-4 py-3 text-slate-600 dark:text-slate-400">{{ scan.scanned_at | date:'short' }}</td>
                      <td class="px-4 py-3">
                        @if (scan.status === 'completed') {
                          <span class="text-green-600 dark:text-green-400">{{ scan.status }}</span>
                        } @else {
                          <span class="text-red-600 dark:text-red-400">{{ scan.status }}</span>
                        }
                      </td>
                      <td class="px-4 py-3 text-slate-900 dark:text-white font-medium">{{ scan.total_findings }}</td>
                      <td class="px-4 py-3">
                        @if (scan.new_findings > 0) {
                          <span class="text-red-600 dark:text-red-400">+{{ scan.new_findings }}</span>
                        } @else {
                          <span class="text-slate-400">0</span>
                        }
                      </td>
                      <td class="px-4 py-3">
                        @if (scan.resolved_findings > 0) {
                          <span class="text-green-600 dark:text-green-400">-{{ scan.resolved_findings }}</span>
                        } @else {
                          <span class="text-slate-400">0</span>
                        }
                      </td>
                      <td class="px-4 py-3 text-slate-600 dark:text-slate-400">{{ scan.trigger }}</td>
                      <td class="px-4 py-3">
                        <a
                          [routerLink]="['/sbom', projectId, 'scans', scan.id]"
                          class="text-blue-600 hover:text-blue-800 dark:text-blue-400 dark:hover:text-blue-300 font-medium"
                          i18n="@@sbom.detail.viewDetailButton"
                        >
                          Details
                        </a>
                      </td>
                    </tr>
                  }
                </tbody>
              </table>
            </div>
          }
        </div>
      }
    </div>
  `,
})
export class SbomProjectDetailComponent implements OnInit, OnDestroy {
  private readonly sbomService = inject(SbomService);
  private readonly statsTrendService = inject(StatsTrendService);
  private readonly themeService = inject(ThemeService);
  private readonly route = inject(ActivatedRoute);

  readonly project = signal<SBOMProject | null>(null);
  readonly versions = signal<SBOMVersion[]>([]);
  readonly versionsLoading = signal(true);
  readonly scanResults = signal<SBOMScanResult[]>([]);
  readonly scansLoading = signal(false);
  readonly selectedVersion = signal<SBOMVersion | null>(null);
  readonly trendData = signal<StatsTrendResponse | null>(null);
  readonly selectedProjectTrendRange = signal('90d');

  readonly trendRanges = [
    { value: '30d', label: $localize`:@@sbom.detail.trendRange30d:30d` },
    { value: '90d', label: $localize`:@@sbom.detail.trendRange90d:90d` },
    { value: '180d', label: $localize`:@@sbom.detail.trendRange180d:180d` },
    { value: '365d', label: $localize`:@@sbom.detail.trendRange365d:365d` },
  ];

  @ViewChild('projectTrendCanvas') projectTrendCanvasRef!: ElementRef<HTMLCanvasElement>;
  private projectTrendChart: Chart | null = null;
  private chartRendered = false;

  // Upload form
  readonly showUploadForm = signal(false);
  readonly uploading = signal(false);
  readonly uploadError = signal<string | null>(null);
  readonly selectedFile = signal<File | null>(null);
  uploadVersion = '';
  uploadEnvironment = '';

  projectId = 0;

  constructor() {
    effect(() => {
      // Track theme mode signal to trigger re-render on theme change
      this.themeService.mode();
      if (this.chartRendered) {
        setTimeout(() => this.renderProjectTrendChart(), 50);
      }
    });
  }

  ngOnInit(): void {
    this.projectId = Number(this.route.snapshot.paramMap.get('id'));
    this.loadProject();
    this.loadVersions();
    this.loadProjectTrend('90d');
  }

  ngOnDestroy(): void {
    if (this.projectTrendChart) {
      this.projectTrendChart.destroy();
    }
  }

  private loadProjectTrend(range: string): void {
    this.statsTrendService.getTrend({ project_id: this.projectId, range, group_by: 'day' }).subscribe({
      next: (data) => {
        this.trendData.set(data);
        setTimeout(() => this.renderProjectTrendChart(), 0);
      },
      error: (err) => {
        console.error('Failed to load project trend data', err);
      },
    });
  }

  onProjectTrendRangeChange(range: string): void {
    this.selectedProjectTrendRange.set(range);
    this.loadProjectTrend(range);
  }

  private renderProjectTrendChart(): void {
    const data = this.trendData();
    if (!data || !this.projectTrendCanvasRef) return;

    const ctx = this.projectTrendCanvasRef.nativeElement.getContext('2d');
    if (!ctx) return;

    if (this.projectTrendChart) {
      this.projectTrendChart.destroy();
      this.projectTrendChart = null;
    }

    const dataPoints = data.data_points;
    const labels = dataPoints.map((d) => d.date);

    this.projectTrendChart = new Chart(ctx, {
      type: 'bar',
      data: {
        labels,
        datasets: [
          {
            type: 'line',
            label: $localize`:@@sbom.detail.chartTotalFindings:Total Findings`,
            data: dataPoints.map((d) => d.total),
            borderColor: '#6366f1',
            backgroundColor: 'rgba(99, 102, 241, 0.1)',
            fill: false,
            tension: 0.3,
            pointRadius: dataPoints.length > 60 ? 0 : 2,
            pointHoverRadius: 4,
            borderWidth: 2,
            yAxisID: 'y',
            order: 1,
          },
          {
            type: 'bar',
            label: $localize`:@@sbom.detail.chartNewFindings:New`,
            data: dataPoints.map((d) => d.new ?? 0),
            backgroundColor: 'rgba(239, 68, 68, 0.7)',
            borderColor: '#ef4444',
            borderWidth: 1,
            yAxisID: 'y1',
            stack: 'changes',
            order: 2,
          },
          {
            type: 'bar',
            label: $localize`:@@sbom.detail.chartResolved:Resolved`,
            data: dataPoints.map((d) => d.resolved ?? 0),
            backgroundColor: 'rgba(34, 197, 94, 0.7)',
            borderColor: '#22c55e',
            borderWidth: 1,
            yAxisID: 'y1',
            stack: 'changes',
            order: 3,
          },
        ],
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        interaction: { intersect: false, mode: 'index' },
        plugins: {
          legend: {
            display: true,
            position: 'top',
            labels: { color: this.tickColor, font: { size: 11 }, usePointStyle: true },
          },
        },
        scales: {
          x: {
            ticks: { maxTicksLimit: 10, font: { size: 10 }, color: this.tickColor },
            grid: { display: false },
          },
          y: {
            type: 'linear',
            position: 'left',
            beginAtZero: true,
            ticks: { font: { size: 10 }, color: this.tickColor },
            grid: { color: this.gridColor },
            title: {
              display: true,
              text: $localize`:@@sbom.detail.axisTotal:Total`,
              color: this.tickColor,
              font: { size: 10 },
            },
          },
          y1: {
            type: 'linear',
            position: 'right',
            beginAtZero: true,
            ticks: { font: { size: 10 }, color: this.tickColor },
            grid: { display: false },
            title: {
              display: true,
              text: $localize`:@@sbom.detail.axisChanges:Changes`,
              color: this.tickColor,
              font: { size: 10 },
            },
          },
        },
      },
    });
    this.chartRendered = true;
  }

  private get tickColor(): string {
    return document.documentElement.classList.contains('dark')
      ? 'rgba(226, 232, 240, 0.8)'
      : 'rgba(100, 116, 139, 0.8)';
  }

  private get gridColor(): string {
    return document.documentElement.classList.contains('dark')
      ? 'rgba(148, 163, 184, 0.15)'
      : 'rgba(148, 163, 184, 0.2)';
  }

  private loadProject(): void {
    this.sbomService.getProject(this.projectId).subscribe({
      next: (project) => this.project.set(project),
    });
  }

  private loadVersions(): void {
    this.versionsLoading.set(true);
    this.sbomService.listVersions(this.projectId).subscribe({
      next: (versions) => {
        this.versions.set(versions);
        this.versionsLoading.set(false);
      },
      error: () => {
        this.versionsLoading.set(false);
      },
    });
  }

  onFileSelected(event: Event): void {
    const input = event.target as HTMLInputElement;
    if (input.files && input.files.length > 0) {
      this.selectedFile.set(input.files[0]);
    } else {
      this.selectedFile.set(null);
    }
  }

  onUpload(): void {
    const file = this.selectedFile();
    if (!file || !this.uploadVersion) return;

    this.uploading.set(true);
    this.uploadError.set(null);

    const reader = new FileReader();
    reader.onload = () => {
      try {
        const sbomContent = JSON.parse(reader.result as string);
        this.sbomService.uploadSBOM(this.projectId, this.uploadVersion, this.uploadEnvironment, sbomContent).subscribe({
          next: () => {
            this.uploading.set(false);
            this.showUploadForm.set(false);
            this.uploadVersion = '';
            this.uploadEnvironment = '';
            this.selectedFile.set(null);
            this.loadVersions();
          },
          error: (err) => {
            this.uploading.set(false);
            this.uploadError.set(err?.error?.error || 'Upload failed');
          },
        });
      } catch {
        this.uploading.set(false);
        this.uploadError.set('Invalid JSON file');
      }
    };
    reader.readAsText(file);
  }

  onViewScans(version: SBOMVersion): void {
    this.selectedVersion.set(version);
    this.scansLoading.set(true);
    this.sbomService.listScanResults(version.id).subscribe({
      next: (results) => {
        this.scanResults.set(results);
        this.scansLoading.set(false);
      },
      error: () => {
        this.scansLoading.set(false);
      },
    });
  }
}

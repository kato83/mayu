import {
  Component,
  ElementRef,
  ViewChild,
  AfterViewInit,
  OnDestroy,
  inject,
  signal,
  effect,
} from '@angular/core';
import { RouterLink } from '@angular/router';
import { DecimalPipe } from '@angular/common';
import { forkJoin } from 'rxjs';
import { Chart, registerables } from 'chart.js';

import { DashboardService } from '../../services/dashboard.service';
import { ThemeService } from '../../services/theme.service';
import {
  DashboardSummary,
  DashboardTrends,
  DashboardDistributions,
  DashboardTopRisks,
} from '../../models/dashboard.model';

Chart.register(...registerables);

@Component({
  selector: 'app-dashboard',
  standalone: true,
  imports: [RouterLink, DecimalPipe],
  template: `
    <!-- Loading state -->
    @if (loading()) {
      <div class="flex items-center justify-center h-64">
        <div class="animate-spin rounded-full h-12 w-12 border-b-2 border-indigo-500"></div>
      </div>
    } @else {
      <!-- Summary cards -->
      <section class="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-4 mb-6">
        <div class="bg-white dark:bg-slate-800 rounded-lg shadow p-4">
          <p class="text-xs text-slate-500 dark:text-slate-400 uppercase tracking-wide" i18n="@@dashboard.totalVulnerabilities">Total Vulnerabilities</p>
          <p class="text-2xl font-bold text-slate-900 dark:text-white mt-1">{{ summary()?.total_vulnerabilities ?? 0 | number }}</p>
        </div>
        <div class="bg-white dark:bg-slate-800 rounded-lg shadow p-4">
          <p class="text-xs text-slate-500 dark:text-slate-400 uppercase tracking-wide" i18n="@@dashboard.last7Days">Last 7 Days</p>
          <p class="text-2xl font-bold text-slate-900 dark:text-white mt-1">{{ summary()?.last_7_days ?? 0 | number }}</p>
        </div>
        <div class="bg-white dark:bg-slate-800 rounded-lg shadow p-4">
          <p class="text-xs text-slate-500 dark:text-slate-400 uppercase tracking-wide" i18n="@@dashboard.last30Days">Last 30 Days</p>
          <p class="text-2xl font-bold text-slate-900 dark:text-white mt-1">{{ summary()?.last_30_days ?? 0 | number }}</p>
        </div>
        <div class="bg-white dark:bg-slate-800 rounded-lg shadow p-4">
          <p class="text-xs text-slate-500 dark:text-slate-400 uppercase tracking-wide" i18n="@@dashboard.critical">Critical</p>
          <p class="text-2xl font-bold text-red-500 mt-1">{{ summary()?.critical_count ?? 0 | number }}</p>
        </div>
        <div class="bg-white dark:bg-slate-800 rounded-lg shadow p-4">
          <p class="text-xs text-slate-500 dark:text-slate-400 uppercase tracking-wide" i18n="@@dashboard.high">High</p>
          <p class="text-2xl font-bold text-orange-500 mt-1">{{ summary()?.high_count ?? 0 | number }}</p>
        </div>
        <div class="bg-white dark:bg-slate-800 rounded-lg shadow p-4">
          <p class="text-xs text-slate-500 dark:text-slate-400 uppercase tracking-wide" i18n="@@dashboard.inKev">In KEV</p>
          <p class="text-2xl font-bold text-amber-600 dark:text-amber-400 mt-1">{{ summary()?.in_kev_count ?? 0 | number }}</p>
        </div>
      </section>

      <!-- Trend chart -->
      <section class="bg-white dark:bg-slate-800 rounded-lg shadow p-4 mb-6">
        <h2 class="text-sm font-semibold text-slate-700 dark:text-slate-200 mb-3" i18n="@@dashboard.trendTitle">New Vulnerabilities (Last 30 Days)</h2>
        <div class="relative w-full" style="height: 220px">
          <canvas #trendCanvas></canvas>
        </div>
      </section>

      <!-- Distribution charts: severity + ecosystems -->
      <section class="grid grid-cols-1 lg:grid-cols-3 gap-6 mb-6">
        <div class="bg-white dark:bg-slate-800 rounded-lg shadow p-4">
          <h2 class="text-sm font-semibold text-slate-700 dark:text-slate-200 mb-3" i18n="@@dashboard.severityWorst">Severity (Worst Case)</h2>
          <div class="relative w-full" style="height: 260px">
            <canvas #severityCanvas></canvas>
          </div>
        </div>
        <div class="bg-white dark:bg-slate-800 rounded-lg shadow p-4">
          <h2 class="text-sm font-semibold text-slate-700 dark:text-slate-200 mb-3" i18n="@@dashboard.severityBest">Severity (Best Case)</h2>
          <div class="relative w-full" style="height: 260px">
            <canvas #severityBestCanvas></canvas>
          </div>
        </div>
        <div class="bg-white dark:bg-slate-800 rounded-lg shadow p-4">
          <h2 class="text-sm font-semibold text-slate-700 dark:text-slate-200 mb-3" i18n="@@dashboard.topEcosystems">Top Ecosystems</h2>
          <div class="relative w-full" style="height: 260px">
            <canvas #ecosystemsCanvas></canvas>
          </div>
        </div>
      </section>

      <!-- EPSS + LEV histograms -->
      <section class="grid grid-cols-1 lg:grid-cols-2 gap-6 mb-6">
        <div class="bg-white dark:bg-slate-800 rounded-lg shadow p-4">
          <h2 class="text-sm font-semibold text-slate-700 dark:text-slate-200 mb-3" i18n="@@dashboard.epssDistribution">EPSS Score Distribution</h2>
          <div class="relative w-full" style="height: 220px">
            <canvas #epssCanvas></canvas>
          </div>
        </div>
        <div class="bg-white dark:bg-slate-800 rounded-lg shadow p-4">
          <h2 class="text-sm font-semibold text-slate-700 dark:text-slate-200 mb-3" i18n="@@dashboard.levDistribution">LEV Score Distribution</h2>
          <div class="relative w-full" style="height: 220px">
            <canvas #levCanvas></canvas>
          </div>
        </div>
      </section>

      <!-- Top risks tables -->
      <section class="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <!-- Top EPSS -->
        <div class="bg-white dark:bg-slate-800 rounded-lg shadow p-4">
          <h2 class="text-sm font-semibold text-slate-700 dark:text-slate-200 mb-3" i18n="@@dashboard.topEpss">Top EPSS Vulnerabilities</h2>
          <div class="overflow-x-auto">
            <table class="w-full text-sm text-left">
              <thead>
                <tr class="text-xs text-slate-500 dark:text-slate-400 border-b border-slate-200 dark:border-slate-700">
                  <th class="pb-2 font-medium" i18n="@@dashboard.tableId">ID</th>
                  <th class="pb-2 font-medium" i18n="@@dashboard.tableEpss">EPSS</th>
                  <th class="pb-2 font-medium" i18n="@@dashboard.tableSeverity">Severity</th>
                </tr>
              </thead>
              <tbody>
                @for (entry of topRisks()?.top_epss ?? []; track entry.vulnerability_id) {
                  <tr class="border-b border-slate-100 dark:border-slate-700/50">
                    <td class="py-2">
                      <a [routerLink]="['/vulnerabilities', entry.vulnerability_id]"
                         class="text-indigo-600 dark:text-indigo-400 hover:underline font-mono text-xs">
                        {{ entry.vulnerability_id }}
                      </a>
                    </td>
                    <td class="py-2 font-mono text-xs text-slate-700 dark:text-slate-200">{{ (entry.score * 100).toFixed(1) }}%</td>
                    <td class="py-2">
                      <span [class]="severityBadgeClass(entry.severity)">{{ entry.severity ?? '-' }}</span>
                    </td>
                  </tr>
                }
              </tbody>
            </table>
          </div>
        </div>

        <!-- Top LEV -->
        <div class="bg-white dark:bg-slate-800 rounded-lg shadow p-4">
          <h2 class="text-sm font-semibold text-slate-700 dark:text-slate-200 mb-3" i18n="@@dashboard.topLev">Top LEV Vulnerabilities</h2>
          <div class="overflow-x-auto">
            <table class="w-full text-sm text-left">
              <thead>
                <tr class="text-xs text-slate-500 dark:text-slate-400 border-b border-slate-200 dark:border-slate-700">
                  <th class="pb-2 font-medium" i18n="@@dashboard.tableId">ID</th>
                  <th class="pb-2 font-medium" i18n="@@dashboard.tableLev">LEV</th>
                  <th class="pb-2 font-medium" i18n="@@dashboard.tableSeverity">Severity</th>
                </tr>
              </thead>
              <tbody>
                @for (entry of topRisks()?.top_lev ?? []; track entry.vulnerability_id) {
                  <tr class="border-b border-slate-100 dark:border-slate-700/50">
                    <td class="py-2">
                      <a [routerLink]="['/vulnerabilities', entry.vulnerability_id]"
                         class="text-indigo-600 dark:text-indigo-400 hover:underline font-mono text-xs">
                        {{ entry.vulnerability_id }}
                      </a>
                    </td>
                    <td class="py-2 font-mono text-xs text-slate-700 dark:text-slate-200">{{ (entry.score * 100).toFixed(1) }}%</td>
                    <td class="py-2">
                      <span [class]="severityBadgeClass(entry.severity)">{{ entry.severity ?? '-' }}</span>
                    </td>
                  </tr>
                }
              </tbody>
            </table>
          </div>
        </div>
      </section>
    }
  `,
})
export class DashboardComponent implements AfterViewInit, OnDestroy {
  private readonly dashboardService = inject(DashboardService);
  private readonly themeService = inject(ThemeService);

  // State signals
  readonly loading = signal(true);
  readonly summary = signal<DashboardSummary | null>(null);
  readonly trends = signal<DashboardTrends | null>(null);
  readonly distributions = signal<DashboardDistributions | null>(null);
  readonly topRisks = signal<DashboardTopRisks | null>(null);

  // Canvas refs
  @ViewChild('trendCanvas') trendCanvasRef!: ElementRef<HTMLCanvasElement>;
  @ViewChild('severityCanvas') severityCanvasRef!: ElementRef<HTMLCanvasElement>;
  @ViewChild('severityBestCanvas') severityBestCanvasRef!: ElementRef<HTMLCanvasElement>;
  @ViewChild('ecosystemsCanvas') ecosystemsCanvasRef!: ElementRef<HTMLCanvasElement>;
  @ViewChild('epssCanvas') epssCanvasRef!: ElementRef<HTMLCanvasElement>;
  @ViewChild('levCanvas') levCanvasRef!: ElementRef<HTMLCanvasElement>;

  // Chart instances for cleanup
  private charts: Chart[] = [];
  private chartsRendered = false;

  constructor() {
    effect(() => {
      // Track theme mode signal to trigger re-render on theme change
      this.themeService.mode();
      if (this.chartsRendered) {
        setTimeout(() => this.renderAllCharts(), 50);
      }
    });
  }

  ngAfterViewInit(): void {
    this.loadData();
  }

  ngOnDestroy(): void {
    this.charts.forEach((c) => c.destroy());
  }

  private loadData(): void {
    forkJoin({
      summary: this.dashboardService.getSummary(),
      trends: this.dashboardService.getTrends(30),
      distributions: this.dashboardService.getDistributions(),
      topRisks: this.dashboardService.getTopRisks(10),
    }).subscribe({
      next: (data) => {
        this.summary.set(data.summary);
        this.trends.set(data.trends);
        this.distributions.set(data.distributions);
        this.topRisks.set(data.topRisks);
        this.loading.set(false);

        // Render charts after DOM updates
        setTimeout(() => this.renderAllCharts(), 0);
      },
      error: () => {
        this.loading.set(false);
      },
    });
  }

  private renderAllCharts(): void {
    this.charts.forEach((c) => c.destroy());
    this.charts = [];
    this.renderTrendChart();
    this.renderSeverityChart();
    this.renderSeverityBestChart();
    this.renderEcosystemsChart();
    this.renderEpssHistogram();
    this.renderLevHistogram();
    this.chartsRendered = true;
  }

  private get isDark(): boolean {
    return document.documentElement.classList.contains('dark');
  }

  private get tickColor(): string {
    return this.isDark
      ? 'rgba(226, 232, 240, 0.8)'
      : 'rgba(100, 116, 139, 0.8)';
  }

  private get gridColor(): string {
    return this.isDark
      ? 'rgba(148, 163, 184, 0.15)'
      : 'rgba(148, 163, 184, 0.2)';
  }

  private renderTrendChart(): void {
    const data = this.trends()?.daily_new_vulns;
    if (!data || !this.trendCanvasRef) return;

    const ctx = this.trendCanvasRef.nativeElement.getContext('2d');
    if (!ctx) return;

    const chart = new Chart(ctx, {
      type: 'line',
      data: {
        labels: data.map((d) => d.date),
        datasets: [
          {
            label: $localize`:@@dashboard.chartNewVulns:New Vulnerabilities`,
            data: data.map((d) => d.count),
            borderColor: '#6366f1',
            backgroundColor: 'rgba(99, 102, 241, 0.1)',
            fill: true,
            tension: 0.3,
            pointRadius: data.length > 60 ? 0 : 2,
            pointHoverRadius: 4,
            borderWidth: 2,
          },
        ],
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        interaction: { intersect: false, mode: 'index' },
        plugins: { legend: { display: false } },
        scales: {
          x: {
            ticks: { maxTicksLimit: 8, font: { size: 10 }, color: this.tickColor },
            grid: { display: false },
          },
          y: {
            beginAtZero: true,
            ticks: { font: { size: 10 }, color: this.tickColor },
            grid: { color: this.gridColor },
          },
        },
      },
    });
    this.charts.push(chart);
  }

  private renderSeverityChart(): void {
    const data = this.distributions()?.severity;
    if (!data || !this.severityCanvasRef) return;

    const ctx = this.severityCanvasRef.nativeElement.getContext('2d');
    if (!ctx) return;

    const colorMap: Record<string, string> = {
      CRITICAL: '#ef4444',
      HIGH: '#f97316',
      MEDIUM: '#eab308',
      LOW: '#3b82f6',
      NONE: '#6b7280',
    };

    const chart = new Chart(ctx, {
      type: 'doughnut',
      data: {
        labels: data.map((d) => d.label),
        datasets: [
          {
            data: data.map((d) => d.count),
            backgroundColor: data.map((d) => colorMap[d.label] ?? '#6b7280'),
            borderWidth: 0,
          },
        ],
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: {
          legend: {
            position: 'right',
            labels: { color: this.tickColor, font: { size: 11 } },
          },
        },
      },
    });
    this.charts.push(chart);
  }

  private renderSeverityBestChart(): void {
    const data = this.distributions()?.severity_best;
    if (!data || !this.severityBestCanvasRef) return;

    const ctx = this.severityBestCanvasRef.nativeElement.getContext('2d');
    if (!ctx) return;

    const colorMap: Record<string, string> = {
      CRITICAL: '#ef4444',
      HIGH: '#f97316',
      MEDIUM: '#eab308',
      LOW: '#3b82f6',
      NONE: '#6b7280',
    };

    const chart = new Chart(ctx, {
      type: 'doughnut',
      data: {
        labels: data.map((d) => d.label),
        datasets: [
          {
            data: data.map((d) => d.count),
            backgroundColor: data.map((d) => colorMap[d.label] ?? '#6b7280'),
            borderWidth: 0,
          },
        ],
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: {
          legend: {
            position: 'right',
            labels: { color: this.tickColor, font: { size: 11 } },
          },
        },
      },
    });
    this.charts.push(chart);
  }

  private renderEcosystemsChart(): void {
    const data = this.distributions()?.ecosystems;
    if (!data || !this.ecosystemsCanvasRef) return;

    const ctx = this.ecosystemsCanvasRef.nativeElement.getContext('2d');
    if (!ctx) return;

    // Take top 15
    const top = data.slice(0, 15);

    const chart = new Chart(ctx, {
      type: 'bar',
      data: {
        labels: top.map((d) => d.label),
        datasets: [
          {
            label: $localize`:@@dashboard.chartVulnCount:Vulnerabilities`,
            data: top.map((d) => d.count),
            backgroundColor: 'rgba(99, 102, 241, 0.7)',
            borderColor: '#6366f1',
            borderWidth: 1,
          },
        ],
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        indexAxis: 'y',
        plugins: { legend: { display: false } },
        scales: {
          x: {
            beginAtZero: true,
            ticks: { font: { size: 10 }, color: this.tickColor },
            grid: { color: this.gridColor },
          },
          y: {
            ticks: { font: { size: 10 }, color: this.tickColor },
            grid: { display: false },
          },
        },
      },
    });
    this.charts.push(chart);
  }

  private renderEpssHistogram(): void {
    const data = this.distributions()?.epss_histogram;
    if (!data || !this.epssCanvasRef) return;

    const ctx = this.epssCanvasRef.nativeElement.getContext('2d');
    if (!ctx) return;

    const chart = new Chart(ctx, {
      type: 'bar',
      data: {
        labels: data.map((d) => d.range_label),
        datasets: [
          {
            label: 'EPSS',
            data: data.map((d) => d.count),
            backgroundColor: 'rgba(99, 102, 241, 0.7)',
            borderColor: '#6366f1',
            borderWidth: 1,
          },
        ],
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: { legend: { display: false } },
        scales: {
          x: {
            ticks: { font: { size: 10 }, color: this.tickColor, maxRotation: 45 },
            grid: { display: false },
          },
          y: {
            beginAtZero: true,
            ticks: { font: { size: 10 }, color: this.tickColor },
            grid: { color: this.gridColor },
          },
        },
      },
    });
    this.charts.push(chart);
  }

  private renderLevHistogram(): void {
    const data = this.distributions()?.lev_histogram;
    if (!data || !this.levCanvasRef) return;

    const ctx = this.levCanvasRef.nativeElement.getContext('2d');
    if (!ctx) return;

    const chart = new Chart(ctx, {
      type: 'bar',
      data: {
        labels: data.map((d) => d.range_label),
        datasets: [
          {
            label: 'LEV',
            data: data.map((d) => d.count),
            backgroundColor: 'rgba(234, 179, 8, 0.7)',
            borderColor: '#eab308',
            borderWidth: 1,
          },
        ],
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: { legend: { display: false } },
        scales: {
          x: {
            ticks: { font: { size: 10 }, color: this.tickColor, maxRotation: 45 },
            grid: { display: false },
          },
          y: {
            beginAtZero: true,
            ticks: { font: { size: 10 }, color: this.tickColor },
            grid: { color: this.gridColor },
          },
        },
      },
    });
    this.charts.push(chart);
  }

  /** Returns TailwindCSS classes for severity badge */
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
}

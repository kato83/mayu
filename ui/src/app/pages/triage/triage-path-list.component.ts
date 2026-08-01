import {
  type AfterViewInit,
  Component,
  type ElementRef,
  inject,
  type OnDestroy,
  type OnInit,
  signal,
  ViewChild,
} from '@angular/core';
import { FormsModule } from '@angular/forms';
import { RouterLink } from '@angular/router';
import { Chart, registerables } from 'chart.js';
import type { TriagePath } from '../../models/triage.model';
import { TriageService } from '../../services/triage.service';

Chart.register(...registerables);

@Component({
  selector: 'app-triage-path-list',
  standalone: true,
  imports: [FormsModule, RouterLink],
  template: `
    @if (loading()) {
      <div class="flex items-center justify-center h-64">
        <div class="animate-spin rounded-full h-12 w-12 border-b-2 border-indigo-500"></div>
      </div>
    } @else {
      <!-- Header -->
      <div class="flex items-center justify-between mb-6">
        <h1 class="text-xl font-bold text-slate-900 dark:text-white" i18n="@@triagePaths.title">Triage Paths</h1>
        <a routerLink="/triage"
           class="text-sm text-indigo-600 dark:text-indigo-400 hover:underline"
           i18n="@@triagePaths.backToDashboard">Back to Dashboard</a>
      </div>

      <!-- Filters -->
      <div class="flex items-center gap-3 mb-4 flex-wrap">
        <select
          class="rounded-md border border-slate-300 dark:border-slate-600 bg-white dark:bg-slate-700 text-sm px-3 py-1.5 text-slate-900 dark:text-white"
          [ngModel]="filterPriority()"
          (ngModelChange)="onFilterChange('priority', $event)">
          <option value="" i18n="@@triagePaths.allPriorities">All Priorities</option>
          <option value="Critical">Critical</option>
          <option value="High">High</option>
          <option value="Medium">Medium</option>
          <option value="Low">Low</option>
        </select>
        <select
          class="rounded-md border border-slate-300 dark:border-slate-600 bg-white dark:bg-slate-700 text-sm px-3 py-1.5 text-slate-900 dark:text-white"
          [ngModel]="filterEcosystem()"
          (ngModelChange)="onFilterChange('ecosystem', $event)">
          <option value="" i18n="@@triagePaths.allEcosystems">All Ecosystems</option>
          <option value="npm">npm</option>
          <option value="maven">Maven</option>
          <option value="pypi">PyPI</option>
          <option value="go">Go</option>
          <option value="cargo">Cargo</option>
          <option value="nuget">NuGet</option>
        </select>
      </div>

      <!-- Impact Score Bar Chart (top 10) -->
      @if (paths().length > 0) {
        <section class="bg-white dark:bg-slate-800 rounded-lg shadow p-4 mb-6">
          <h2 class="text-sm font-semibold text-slate-700 dark:text-slate-200 mb-3" i18n="@@triagePaths.impactChart">Impact Score Comparison (Top 10)</h2>
          <div class="relative w-full" style="height: 240px">
            <canvas #impactCanvas></canvas>
          </div>
        </section>
      }

      <!-- Paths Table -->
      <section class="bg-white dark:bg-slate-800 rounded-lg shadow overflow-hidden">
        <div class="overflow-x-auto">
          <table class="w-full text-sm text-left">
            <thead>
              <tr class="text-xs text-slate-500 dark:text-slate-400 border-b border-slate-200 dark:border-slate-700">
                <th class="px-4 py-2 font-medium" i18n="@@triagePaths.colAction">Action</th>
                <th class="px-4 py-2 font-medium" i18n="@@triagePaths.colImpact">Impact Score</th>
                <th class="px-4 py-2 font-medium" i18n="@@triagePaths.colPriority">Priority</th>
                <th class="px-4 py-2 font-medium" i18n="@@triagePaths.colVulns">Resolved CVEs</th>
                <th class="px-4 py-2 font-medium" i18n="@@triagePaths.colServers">Servers</th>
                <th class="px-4 py-2 font-medium" i18n="@@triagePaths.colEcosystem">Ecosystem</th>
                <th class="px-4 py-2 font-medium"></th>
              </tr>
            </thead>
            <tbody>
              @for (path of paths(); track path.id) {
                <tr class="border-b border-slate-100 dark:border-slate-700/50 hover:bg-slate-50 dark:hover:bg-slate-700/30">
                  <td class="px-4 py-2">
                    <div class="text-xs font-mono text-slate-900 dark:text-white">{{ path.action.package_name }}</div>
                    <div class="text-xs text-slate-500 dark:text-slate-400">
                      {{ path.action.current_version }} &rarr; {{ path.action.target_version }}
                    </div>
                  </td>
                  <td class="px-4 py-2">
                    <div class="flex items-center gap-2">
                      <div class="w-16 h-2 bg-slate-200 dark:bg-slate-600 rounded-full overflow-hidden">
                        <div class="h-full bg-indigo-500 rounded-full" [style.width.%]="path.impact_score * 100"></div>
                      </div>
                      <span class="font-mono text-xs text-slate-700 dark:text-slate-200">{{ path.impact_score.toFixed(3) }}</span>
                    </div>
                  </td>
                  <td class="px-4 py-2">
                    <span [class]="priorityBadgeClass(path.max_priority_level)">{{ path.max_priority_level }}</span>
                  </td>
                  <td class="px-4 py-2 text-xs text-slate-600 dark:text-slate-300">{{ path.total_vuln_count }}</td>
                  <td class="px-4 py-2 text-xs text-slate-600 dark:text-slate-300">{{ path.total_server_count }}</td>
                  <td class="px-4 py-2 text-xs text-slate-500 dark:text-slate-400">{{ path.action.ecosystem }}</td>
                  <td class="px-4 py-2">
                    <a [routerLink]="['/triage/paths', path.id]"
                       class="text-xs text-indigo-600 dark:text-indigo-400 hover:underline"
                       i18n="@@triagePaths.viewDetail">Details</a>
                  </td>
                </tr>
              } @empty {
                <tr>
                  <td colspan="7" class="px-4 py-8 text-center text-sm text-slate-500 dark:text-slate-400" i18n="@@triagePaths.noPaths">
                    No triage paths available.
                  </td>
                </tr>
              }
            </tbody>
          </table>
        </div>
      </section>
    }
  `,
})
export class TriagePathListComponent implements OnInit, AfterViewInit, OnDestroy {
  private readonly triageService = inject(TriageService);

  readonly loading = signal(true);
  readonly paths = signal<TriagePath[]>([]);
  readonly filterPriority = signal<string>('');
  readonly filterEcosystem = signal<string>('');

  @ViewChild('impactCanvas') impactCanvasRef!: ElementRef<HTMLCanvasElement>;
  private chart: Chart | null = null;

  ngOnInit(): void {
    this.loadData();
  }

  ngAfterViewInit(): void {
    // Chart will be rendered after data loads
  }

  ngOnDestroy(): void {
    if (this.chart) {
      this.chart.destroy();
    }
  }

  private loadData(): void {
    const opts: { priority?: string; ecosystem?: string; limit?: number } = { limit: 50 };
    if (this.filterPriority()) opts.priority = this.filterPriority();
    if (this.filterEcosystem()) opts.ecosystem = this.filterEcosystem();

    this.triageService.listPaths(opts).subscribe({
      next: (p) => {
        this.paths.set(Array.isArray(p) ? p : []);
        this.loading.set(false);
        setTimeout(() => this.renderChart(), 0);
      },
      error: () => this.loading.set(false),
    });
  }

  onFilterChange(type: string, value: string): void {
    if (type === 'priority') this.filterPriority.set(value);
    if (type === 'ecosystem') this.filterEcosystem.set(value);
    this.loading.set(true);
    this.loadData();
  }

  private renderChart(): void {
    if (!this.impactCanvasRef) return;
    if (this.chart) {
      this.chart.destroy();
      this.chart = null;
    }

    const ctx = this.impactCanvasRef.nativeElement.getContext('2d');
    if (!ctx) return;

    const top10 = this.paths().slice(0, 10);
    const isDark = document.documentElement.classList.contains('dark');
    const tickColor = isDark ? 'rgba(226, 232, 240, 0.8)' : 'rgba(100, 116, 139, 0.8)';
    const gridColor = isDark ? 'rgba(148, 163, 184, 0.15)' : 'rgba(148, 163, 184, 0.2)';

    const priorityColors: Record<string, string> = {
      Critical: 'rgba(239, 68, 68, 0.7)',
      High: 'rgba(249, 115, 22, 0.7)',
      Medium: 'rgba(234, 179, 8, 0.7)',
      Low: 'rgba(59, 130, 246, 0.7)',
    };

    this.chart = new Chart(ctx, {
      type: 'bar',
      data: {
        labels: top10.map((p) => `${p.action.package_name} (${p.total_vuln_count} CVEs)`),
        datasets: [
          {
            label: 'Impact Score',
            data: top10.map((p) => p.impact_score),
            backgroundColor: top10.map((p) => priorityColors[p.max_priority_level] ?? 'rgba(99, 102, 241, 0.7)'),
            borderWidth: 0,
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
            ticks: { font: { size: 10 }, color: tickColor },
            grid: { color: gridColor },
          },
          y: {
            ticks: { font: { size: 10 }, color: tickColor },
            grid: { display: false },
          },
        },
      },
    });
  }

  priorityBadgeClass(level: string): string {
    const base = 'inline-block px-2 py-0.5 rounded text-xs font-semibold';
    switch (level) {
      case 'Critical':
        return `${base} bg-red-100 text-red-700 dark:bg-red-900/30 dark:text-red-400`;
      case 'High':
        return `${base} bg-orange-100 text-orange-700 dark:bg-orange-900/30 dark:text-orange-400`;
      case 'Medium':
        return `${base} bg-yellow-100 text-yellow-700 dark:bg-yellow-900/30 dark:text-yellow-400`;
      case 'Low':
        return `${base} bg-blue-100 text-blue-700 dark:bg-blue-900/30 dark:text-blue-400`;
      default:
        return `${base} bg-slate-100 text-slate-600 dark:bg-slate-700 dark:text-slate-300`;
    }
  }
}

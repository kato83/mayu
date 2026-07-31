import { DecimalPipe } from '@angular/common';
import { Component, inject, type OnInit, signal } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { RouterLink } from '@angular/router';
import type { CrossProjectTriageResult, TriageOverviewSummary } from '../../models/triage.model';
import { TriageService } from '../../services/triage.service';

@Component({
  selector: 'app-triage-overview',
  standalone: true,
  imports: [DecimalPipe, FormsModule, RouterLink],
  template: `
    @if (loading()) {
      <div class="flex items-center justify-center h-64">
        <div class="animate-spin rounded-full h-12 w-12 border-b-2 border-indigo-500"></div>
      </div>
    } @else {
      <!-- Header -->
      <div class="flex items-center justify-between mb-6">
        <h1 class="text-xl font-bold text-slate-900 dark:text-white" i18n="@@triageOverview.title">Cross-Project Triage Overview</h1>
        <a routerLink="/triage"
           class="text-sm text-indigo-600 dark:text-indigo-400 hover:underline"
           i18n="@@triageOverview.backToDashboard">Back to Dashboard</a>
      </div>

      <!-- Priority Level Summary Cards -->
      <section class="grid grid-cols-2 sm:grid-cols-4 gap-4 mb-6">
        <div class="bg-white dark:bg-slate-800 rounded-lg shadow p-4 border-l-4 border-red-500">
          <p class="text-xs text-slate-500 dark:text-slate-400 uppercase tracking-wide" i18n="@@triageOverview.critical">Critical</p>
          <p class="text-2xl font-bold text-red-500 mt-1">{{ overviewSummary()?.priority_counts?.Critical ?? 0 | number }}</p>
        </div>
        <div class="bg-white dark:bg-slate-800 rounded-lg shadow p-4 border-l-4 border-orange-500">
          <p class="text-xs text-slate-500 dark:text-slate-400 uppercase tracking-wide" i18n="@@triageOverview.high">High</p>
          <p class="text-2xl font-bold text-orange-500 mt-1">{{ overviewSummary()?.priority_counts?.High ?? 0 | number }}</p>
        </div>
        <div class="bg-white dark:bg-slate-800 rounded-lg shadow p-4 border-l-4 border-yellow-500">
          <p class="text-xs text-slate-500 dark:text-slate-400 uppercase tracking-wide" i18n="@@triageOverview.medium">Medium</p>
          <p class="text-2xl font-bold text-yellow-500 mt-1">{{ overviewSummary()?.priority_counts?.Medium ?? 0 | number }}</p>
        </div>
        <div class="bg-white dark:bg-slate-800 rounded-lg shadow p-4 border-l-4 border-blue-500">
          <p class="text-xs text-slate-500 dark:text-slate-400 uppercase tracking-wide" i18n="@@triageOverview.low">Low</p>
          <p class="text-2xl font-bold text-blue-500 mt-1">{{ overviewSummary()?.priority_counts?.Low ?? 0 | number }}</p>
        </div>
      </section>

      <!-- Meta stats -->
      <div class="flex items-center gap-4 mb-4 text-xs text-slate-500 dark:text-slate-400">
        <span>Total: {{ overviewSummary()?.total_vulnerabilities ?? 0 }}</span>
        <span>Projects: {{ overviewSummary()?.total_projects ?? 0 }}</span>
        <span>Servers: {{ overviewSummary()?.total_servers ?? 0 }}</span>
      </div>

      <!-- Filters -->
      <div class="flex items-center gap-3 mb-4">
        <select
          class="rounded-md border border-slate-300 dark:border-slate-600 bg-white dark:bg-slate-700 text-sm px-3 py-1.5 text-slate-900 dark:text-white"
          [ngModel]="filterPriority()"
          (ngModelChange)="onFilterChange($event)">
          <option value="" i18n="@@triageOverview.allPriorities">All Priorities</option>
          <option value="Critical">Critical</option>
          <option value="High">High</option>
          <option value="Medium">Medium</option>
          <option value="Low">Low</option>
        </select>
        <select
          class="rounded-md border border-slate-300 dark:border-slate-600 bg-white dark:bg-slate-700 text-sm px-3 py-1.5 text-slate-900 dark:text-white"
          [ngModel]="sortOption()"
          (ngModelChange)="onSortChange($event)">
          <option value="priority" i18n="@@triageOverview.sortPriority">Sort: Priority</option>
          <option value="affected_count" i18n="@@triageOverview.sortAffected">Sort: Affected Servers</option>
          <option value="score" i18n="@@triageOverview.sortScore">Sort: Score</option>
        </select>
      </div>

      <!-- Vulnerability Table -->
      <section class="bg-white dark:bg-slate-800 rounded-lg shadow overflow-hidden">
        <div class="overflow-x-auto">
          <table class="w-full text-sm text-left">
            <thead>
              <tr class="text-xs text-slate-500 dark:text-slate-400 border-b border-slate-200 dark:border-slate-700">
                <th class="px-4 py-2 font-medium" i18n="@@triageOverview.colId">Vulnerability</th>
                <th class="px-4 py-2 font-medium" i18n="@@triageOverview.colOrgPriority">Org Priority</th>
                <th class="px-4 py-2 font-medium" i18n="@@triageOverview.colScore">Max Score</th>
                <th class="px-4 py-2 font-medium" i18n="@@triageOverview.colProjects">Projects</th>
                <th class="px-4 py-2 font-medium" i18n="@@triageOverview.colServers">Servers</th>
                <th class="px-4 py-2 font-medium w-8"></th>
              </tr>
            </thead>
            <tbody>
              @for (item of vulnerabilities(); track item.vulnerability_id) {
                <tr class="border-b border-slate-100 dark:border-slate-700/50 hover:bg-slate-50 dark:hover:bg-slate-700/30 cursor-pointer"
                    (click)="toggleExpand(item.vulnerability_id)">
                  <td class="px-4 py-2">
                    <a [routerLink]="['/vulnerabilities', item.vulnerability_id]"
                       class="text-indigo-600 dark:text-indigo-400 hover:underline font-mono text-xs"
                       (click)="$event.stopPropagation()">
                      {{ item.vulnerability_id }}
                    </a>
                  </td>
                  <td class="px-4 py-2">
                    <span [class]="priorityBadgeClass(item.org_priority_level)">{{ item.org_priority_level }}</span>
                  </td>
                  <td class="px-4 py-2 font-mono text-xs text-slate-700 dark:text-slate-200">
                    {{ (item.max_composite_score * 100).toFixed(1) }}%
                  </td>
                  <td class="px-4 py-2 text-xs text-slate-600 dark:text-slate-300">{{ item.affected_projects }}</td>
                  <td class="px-4 py-2 text-xs text-slate-600 dark:text-slate-300">{{ item.affected_servers }}</td>
                  <td class="px-4 py-2 text-xs text-slate-400">
                    <span [class]="expandedId() === item.vulnerability_id ? 'rotate-90 inline-block transition-transform' : 'inline-block transition-transform'">&#9654;</span>
                  </td>
                </tr>
                <!-- Expanded row: server breakdown -->
                @if (expandedId() === item.vulnerability_id && item.server_breakdown?.length) {
                  <tr>
                    <td colspan="6" class="px-4 py-2 bg-slate-50 dark:bg-slate-700/20">
                      <div class="overflow-x-auto">
                        <table class="w-full text-xs text-left">
                          <thead>
                            <tr class="text-slate-400 dark:text-slate-500">
                              <th class="px-2 py-1">Project</th>
                              <th class="px-2 py-1">Server</th>
                              <th class="px-2 py-1">Environment</th>
                              <th class="px-2 py-1">Profile</th>
                              <th class="px-2 py-1">Priority</th>
                              <th class="px-2 py-1">Score</th>
                            </tr>
                          </thead>
                          <tbody>
                            @for (entry of item.server_breakdown; track entry.server_label) {
                              <tr class="border-t border-slate-200/50 dark:border-slate-600/50">
                                <td class="px-2 py-1 text-slate-700 dark:text-slate-300">{{ entry.project_name }}</td>
                                <td class="px-2 py-1 font-mono text-slate-600 dark:text-slate-400">{{ entry.server_label }}</td>
                                <td class="px-2 py-1 text-slate-500 dark:text-slate-400">{{ entry.environment }}</td>
                                <td class="px-2 py-1 text-slate-500 dark:text-slate-400">{{ entry.profile_used }}</td>
                                <td class="px-2 py-1">
                                  <span [class]="priorityBadgeClass(entry.triage_result.priority_level)">{{ entry.triage_result.priority_level }}</span>
                                </td>
                                <td class="px-2 py-1 font-mono text-slate-600 dark:text-slate-300">{{ (entry.triage_result.composite_score * 100).toFixed(1) }}%</td>
                              </tr>
                            }
                          </tbody>
                        </table>
                      </div>
                    </td>
                  </tr>
                }
              } @empty {
                <tr>
                  <td colspan="6" class="px-4 py-8 text-center text-sm text-slate-500 dark:text-slate-400" i18n="@@triageOverview.noResults">
                    No cross-project triage data available.
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
export class TriageOverviewComponent implements OnInit {
  private readonly triageService = inject(TriageService);

  readonly loading = signal(true);
  readonly overviewSummary = signal<TriageOverviewSummary | null>(null);
  readonly vulnerabilities = signal<CrossProjectTriageResult[]>([]);
  readonly expandedId = signal<string | null>(null);
  readonly filterPriority = signal<string>('');
  readonly sortOption = signal<string>('priority');

  ngOnInit(): void {
    this.loadData();
  }

  private loadData(): void {
    this.triageService.getOverviewSummary().subscribe({
      next: (s) => this.overviewSummary.set(s),
      error: () => {},
    });

    const opts: { priority?: string; sort?: string; limit?: number } = { limit: 100 };
    if (this.filterPriority()) opts.priority = this.filterPriority();
    if (this.sortOption()) opts.sort = this.sortOption();

    this.triageService.getOverviewVulnerabilities(opts).subscribe({
      next: (v) => {
        this.vulnerabilities.set(v);
        this.loading.set(false);
      },
      error: () => this.loading.set(false),
    });
  }

  onFilterChange(priority: string): void {
    this.filterPriority.set(priority);
    this.loading.set(true);
    this.loadData();
  }

  onSortChange(sort: string): void {
    this.sortOption.set(sort);
    this.loading.set(true);
    this.loadData();
  }

  toggleExpand(id: string): void {
    this.expandedId.set(this.expandedId() === id ? null : id);
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

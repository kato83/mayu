import { DecimalPipe } from '@angular/common';
import { Component, inject, type OnInit, signal } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { RouterLink } from '@angular/router';
import type { PriorityLevel, TriageProfile, TriageResult, TriageSummary } from '../../models/triage.model';
import { TriageService } from '../../services/triage.service';

@Component({
  selector: 'app-triage-dashboard',
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
        <h1 class="text-xl font-bold text-slate-900 dark:text-white" i18n="@@triage.dashboardTitle">Triage Dashboard</h1>
        <div class="flex items-center gap-3">
          <label class="text-sm text-slate-600 dark:text-slate-400" i18n="@@triage.profileLabel">Profile:</label>
          <select
            class="rounded-md border border-slate-300 dark:border-slate-600 bg-white dark:bg-slate-700 text-sm px-3 py-1.5 text-slate-900 dark:text-white"
            [ngModel]="selectedProfile()"
            (ngModelChange)="onProfileChange($event)">
            @for (p of profiles(); track p.name) {
              <option [value]="p.name">{{ p.name }}</option>
            }
          </select>
        </div>
      </div>

      <!-- Priority Level Summary Cards -->
      <section class="grid grid-cols-2 sm:grid-cols-4 gap-4 mb-6">
        <div class="bg-white dark:bg-slate-800 rounded-lg shadow p-4 border-l-4 border-red-500">
          <p class="text-xs text-slate-500 dark:text-slate-400 uppercase tracking-wide" i18n="@@triage.critical">Critical</p>
          <p class="text-2xl font-bold text-red-500 mt-1">{{ summary()?.critical ?? 0 | number }}</p>
        </div>
        <div class="bg-white dark:bg-slate-800 rounded-lg shadow p-4 border-l-4 border-orange-500">
          <p class="text-xs text-slate-500 dark:text-slate-400 uppercase tracking-wide" i18n="@@triage.high">High</p>
          <p class="text-2xl font-bold text-orange-500 mt-1">{{ summary()?.high ?? 0 | number }}</p>
        </div>
        <div class="bg-white dark:bg-slate-800 rounded-lg shadow p-4 border-l-4 border-yellow-500">
          <p class="text-xs text-slate-500 dark:text-slate-400 uppercase tracking-wide" i18n="@@triage.medium">Medium</p>
          <p class="text-2xl font-bold text-yellow-500 mt-1">{{ summary()?.medium ?? 0 | number }}</p>
        </div>
        <div class="bg-white dark:bg-slate-800 rounded-lg shadow p-4 border-l-4 border-blue-500">
          <p class="text-xs text-slate-500 dark:text-slate-400 uppercase tracking-wide" i18n="@@triage.low">Low</p>
          <p class="text-2xl font-bold text-blue-500 mt-1">{{ summary()?.low ?? 0 | number }}</p>
        </div>
      </section>

      <!-- Meta info -->
      <div class="flex items-center gap-4 mb-4 text-xs text-slate-500 dark:text-slate-400">
        <span i18n="@@triage.totalTriaged">Total triaged: {{ summary()?.total_triaged ?? 0 }}</span>
        <span i18n="@@triage.profileUsed">Profile: {{ summary()?.profile_used ?? 'default' }}</span>
        @if (summary()?.last_computed) {
          <span i18n="@@triage.lastComputed">Last computed: {{ summary()?.last_computed }}</span>
        }
      </div>

      <!-- Triage Results Table -->
      <section class="bg-white dark:bg-slate-800 rounded-lg shadow overflow-hidden">
        <div class="px-4 py-3 border-b border-slate-200 dark:border-slate-700">
          <h2 class="text-sm font-semibold text-slate-700 dark:text-slate-200" i18n="@@triage.resultsTitle">Triage Results</h2>
        </div>
        <div class="overflow-x-auto">
          <table class="w-full text-sm text-left">
            <thead>
              <tr class="text-xs text-slate-500 dark:text-slate-400 border-b border-slate-200 dark:border-slate-700">
                <th class="px-4 py-2 font-medium cursor-pointer hover:text-slate-700 dark:hover:text-slate-200" (click)="sortBy('vulnerability_id')" i18n="@@triage.colId">Vulnerability</th>
                <th class="px-4 py-2 font-medium cursor-pointer hover:text-slate-700 dark:hover:text-slate-200" (click)="sortBy('priority_level')" i18n="@@triage.colPriority">Priority</th>
                <th class="px-4 py-2 font-medium cursor-pointer hover:text-slate-700 dark:hover:text-slate-200" (click)="sortBy('composite_score')" i18n="@@triage.colScore">Score</th>
                <th class="px-4 py-2 font-medium" i18n="@@triage.colSSVC">SSVC</th>
                <th class="px-4 py-2 font-medium" i18n="@@triage.colRationale">Rationale</th>
              </tr>
            </thead>
            <tbody>
              @for (result of results(); track result.vulnerability_id) {
                <tr class="border-b border-slate-100 dark:border-slate-700/50 hover:bg-slate-50 dark:hover:bg-slate-700/30">
                  <td class="px-4 py-2">
                    <a [routerLink]="['/vulnerabilities', result.vulnerability_id]"
                       class="text-indigo-600 dark:text-indigo-400 hover:underline font-mono text-xs">
                      {{ result.vulnerability_id }}
                    </a>
                  </td>
                  <td class="px-4 py-2">
                    <span [class]="priorityBadgeClass(result.priority_level)">{{ result.priority_level }}</span>
                  </td>
                  <td class="px-4 py-2 font-mono text-xs text-slate-700 dark:text-slate-200">
                    {{ (result.composite_score * 100).toFixed(1) }}%
                  </td>
                  <td class="px-4 py-2 text-xs text-slate-600 dark:text-slate-300">
                    {{ result.ssvc_decision }}
                  </td>
                  <td class="px-4 py-2 text-xs text-slate-500 dark:text-slate-400 max-w-xs truncate">
                    {{ result.rationale?.summary ?? '-' }}
                  </td>
                </tr>
              } @empty {
                <tr>
                  <td colspan="5" class="px-4 py-8 text-center text-sm text-slate-500 dark:text-slate-400" i18n="@@triage.noResults">
                    No triage results available. Run a triage scan to get started.
                  </td>
                </tr>
              }
            </tbody>
          </table>
        </div>
      </section>

      <!-- Quick links -->
      <div class="mt-6 flex gap-3">
        <a routerLink="/triage/overview"
           class="inline-flex items-center px-3 py-2 text-sm font-medium rounded-md bg-indigo-50 dark:bg-indigo-900/30 text-indigo-700 dark:text-indigo-300 hover:bg-indigo-100 dark:hover:bg-indigo-900/50"
           i18n="@@triage.viewOverview">Cross-Project Overview</a>
        <a routerLink="/triage/paths"
           class="inline-flex items-center px-3 py-2 text-sm font-medium rounded-md bg-indigo-50 dark:bg-indigo-900/30 text-indigo-700 dark:text-indigo-300 hover:bg-indigo-100 dark:hover:bg-indigo-900/50"
           i18n="@@triage.viewPaths">Triage Paths</a>
      </div>
    }
  `,
})
export class TriageDashboardComponent implements OnInit {
  private readonly triageService = inject(TriageService);

  readonly loading = signal(true);
  readonly summary = signal<TriageSummary | null>(null);
  readonly results = signal<TriageResult[]>([]);
  readonly profiles = signal<TriageProfile[]>([]);
  readonly selectedProfile = signal<string>('default');

  private sortField: string = 'priority_level';
  private sortAsc = false;

  ngOnInit(): void {
    this.loadData();
  }

  private loadData(): void {
    this.triageService.getDashboardSummary().subscribe({
      next: (s) => this.summary.set(s),
      error: () => {},
    });

    this.triageService.listProfiles().subscribe({
      next: (p) => this.profiles.set(p),
      error: () => {},
    });

    this.triageService.triageBatch({}).subscribe({
      next: (r) => {
        this.results.set(r);
        this.loading.set(false);
      },
      error: () => this.loading.set(false),
    });
  }

  onProfileChange(profile: string): void {
    this.selectedProfile.set(profile);
    this.loading.set(true);
    this.loadData();
  }

  sortBy(field: string): void {
    if (this.sortField === field) {
      this.sortAsc = !this.sortAsc;
    } else {
      this.sortField = field;
      this.sortAsc = true;
    }

    const priorityOrder: Record<string, number> = { Critical: 0, High: 1, Medium: 2, Low: 3 };
    const sorted = [...this.results()].sort((a, b) => {
      let cmp = 0;
      if (field === 'priority_level') {
        cmp = (priorityOrder[a.priority_level] ?? 4) - (priorityOrder[b.priority_level] ?? 4);
      } else if (field === 'composite_score') {
        cmp = a.composite_score - b.composite_score;
      } else if (field === 'vulnerability_id') {
        cmp = a.vulnerability_id.localeCompare(b.vulnerability_id);
      }
      return this.sortAsc ? cmp : -cmp;
    });
    this.results.set(sorted);
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

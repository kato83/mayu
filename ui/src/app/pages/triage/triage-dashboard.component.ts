import { DatePipe } from '@angular/common';
import { Component, inject, type OnInit, signal } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { RouterLink } from '@angular/router';
import type { SBOMProject } from '../../models/sbom.model';
import type {
  CrossProjectTriageResult,
  TriageOverviewSummary,
  TriageProfile,
  TriageResult,
} from '../../models/triage.model';
import { SbomService } from '../../services/sbom.service';
import { TriageService } from '../../services/triage.service';

@Component({
  selector: 'app-triage-dashboard',
  standalone: true,
  imports: [DatePipe, FormsModule, RouterLink],
  template: `
    @if (loading()) {
      <div class="flex items-center justify-center h-64">
        <div class="animate-spin rounded-full h-12 w-12 border-b-2 border-indigo-500"></div>
      </div>
    } @else {
      <!-- Organization-wide Priority Summary Cards -->
      <section class="grid grid-cols-2 sm:grid-cols-4 gap-4 mb-6">
        <div class="bg-white dark:bg-slate-800 rounded-lg shadow p-4 border-l-4 border-red-500">
          <p class="text-xs text-slate-500 dark:text-slate-400 uppercase tracking-wide" i18n="@@triage.critical">Critical</p>
          <p class="text-2xl font-bold text-red-500 mt-1">{{ overviewSummary()?.priority_counts?.Critical ?? 0 }}</p>
        </div>
        <div class="bg-white dark:bg-slate-800 rounded-lg shadow p-4 border-l-4 border-orange-500">
          <p class="text-xs text-slate-500 dark:text-slate-400 uppercase tracking-wide" i18n="@@triage.high">High</p>
          <p class="text-2xl font-bold text-orange-500 mt-1">{{ overviewSummary()?.priority_counts?.High ?? 0 }}</p>
        </div>
        <div class="bg-white dark:bg-slate-800 rounded-lg shadow p-4 border-l-4 border-yellow-500">
          <p class="text-xs text-slate-500 dark:text-slate-400 uppercase tracking-wide" i18n="@@triage.medium">Medium</p>
          <p class="text-2xl font-bold text-yellow-500 mt-1">{{ overviewSummary()?.priority_counts?.Medium ?? 0 }}</p>
        </div>
        <div class="bg-white dark:bg-slate-800 rounded-lg shadow p-4 border-l-4 border-blue-500">
          <p class="text-xs text-slate-500 dark:text-slate-400 uppercase tracking-wide" i18n="@@triage.low">Low</p>
          <p class="text-2xl font-bold text-blue-500 mt-1">{{ overviewSummary()?.priority_counts?.Low ?? 0 }}</p>
        </div>
      </section>

      <!-- Organization meta stats -->
      <div class="flex items-center gap-4 mb-6 text-xs text-slate-500 dark:text-slate-400">
        <span i18n="@@triage.orgTotal">Total vulnerabilities: {{ overviewSummary()?.total_vulnerabilities ?? 0 }}</span>
        <span i18n="@@triage.orgProjects">Projects: {{ overviewSummary()?.total_projects ?? 0 }}</span>
      </div>

      <!-- Top Risks (from cross-project overview) -->
      @if (topRisks().length > 0) {
        <section class="bg-white dark:bg-slate-800 rounded-lg shadow overflow-hidden mb-6">
          <div class="px-4 py-3 border-b border-slate-200 dark:border-slate-700 flex items-center justify-between">
            <h2 class="text-sm font-semibold text-slate-700 dark:text-slate-200" i18n="@@triage.topRisksTitle">Top Risks Across Projects</h2>
            <a routerLink="/triage/overview"
               class="text-xs text-indigo-600 dark:text-indigo-400 hover:underline"
               i18n="@@triage.viewAllOverview">View all</a>
          </div>
          <div class="overflow-x-auto">
            <table class="w-full text-sm text-left">
              <thead>
                <tr class="text-xs text-slate-500 dark:text-slate-400 border-b border-slate-200 dark:border-slate-700">
                  <th class="px-4 py-2 font-medium whitespace-nowrap" i18n="@@triage.colId">Vulnerability</th>
                  <th class="px-4 py-2 font-medium whitespace-nowrap" i18n="@@triage.colPriority">Priority</th>
                  <th class="px-4 py-2 font-medium whitespace-nowrap" i18n="@@triage.colScore">Score</th>
                  <th class="px-4 py-2 font-medium whitespace-nowrap" i18n="@@triage.topRisksColProjects">Projects</th>
                </tr>
              </thead>
              <tbody>
                @for (item of topRisks(); track item.vulnerability_id) {
                  <tr class="border-b border-slate-100 dark:border-slate-700/50 hover:bg-slate-50 dark:hover:bg-slate-700/30">
                    <td class="px-4 py-2">
                      <a [routerLink]="['/vulnerabilities', item.vulnerability_id]"
                         class="text-indigo-600 dark:text-indigo-400 hover:underline font-mono text-xs">
                        {{ item.vulnerability_id }}
                      </a>
                    </td>
                    <td class="px-4 py-2">
                      <span [class]="priorityBadgeClass(item.org_priority_level)">{{ item.org_priority_level }}</span>
                    </td>
                    <td class="px-4 py-2 font-mono text-xs text-slate-700 dark:text-slate-200">
                      {{ (item.max_composite_score * 100).toFixed(1) }}%
                    </td>
                    <td class="px-4 py-2 text-xs text-slate-600 dark:text-slate-300">
                      {{ item.affected_projects }}
                    </td>
                  </tr>
                }
              </tbody>
            </table>
          </div>
        </section>
      }

      <!-- Project List -->
      @if (projects().length > 0) {
        <section class="bg-white dark:bg-slate-800 rounded-lg shadow overflow-hidden mb-6">
          <div class="px-4 py-3 border-b border-slate-200 dark:border-slate-700">
            <h2 class="text-sm font-semibold text-slate-700 dark:text-slate-200" i18n="@@triage.projectsTitle">SBOM Projects</h2>
          </div>
          <div class="overflow-x-auto">
            <table class="w-full text-sm text-left">
              <thead>
                <tr class="text-xs text-slate-500 dark:text-slate-400 border-b border-slate-200 dark:border-slate-700">
                  <th class="px-4 py-2 font-medium whitespace-nowrap" i18n="@@triage.projectColName">Project</th>
                  <th class="px-4 py-2 font-medium whitespace-nowrap" i18n="@@triage.projectColCreated">Created</th>
                  <th class="px-4 py-2 font-medium whitespace-nowrap" i18n="@@triage.projectColAction">Action</th>
                </tr>
              </thead>
              <tbody>
                @for (proj of projects(); track proj.id) {
                  <tr class="border-b border-slate-100 dark:border-slate-700/50 hover:bg-slate-50 dark:hover:bg-slate-700/30">
                    <td class="px-4 py-2 text-sm text-slate-700 dark:text-slate-200">{{ proj.name }}</td>
                    <td class="px-4 py-2 text-xs text-slate-500 dark:text-slate-400">{{ proj.created_at | date }}</td>
                    <td class="px-4 py-2">
                      <button
                        class="text-xs text-indigo-600 dark:text-indigo-400 hover:underline"
                        (click)="runTriageForProject(proj)"
                        [disabled]="triageRunning()"
                        i18n="@@triage.runForProject">Run Triage</button>
                    </td>
                  </tr>
                }
              </tbody>
            </table>
          </div>
        </section>
      } @else {
        <section class="bg-white dark:bg-slate-800 rounded-lg shadow p-6 mb-6 text-center">
          <p class="text-sm text-slate-500 dark:text-slate-400" i18n="@@triage.noProjects">
            No SBOM projects found. Upload an SBOM to get started with vulnerability triage.
          </p>
          <a routerLink="/sbom"
             class="mt-3 inline-flex items-center px-3 py-2 text-sm font-medium rounded-md bg-indigo-600 text-white hover:bg-indigo-700"
             i18n="@@triage.goToSbom">Go to SBOM Management</a>
        </section>
      }

      <!-- Run Triage (Manual) -->
      <section class="bg-white dark:bg-slate-800 rounded-lg shadow p-4 mb-6">
        <h2 class="text-sm font-semibold text-slate-700 dark:text-slate-200 mb-3" i18n="@@triage.runTriageTitle">Run Triage</h2>
        <p class="text-xs text-slate-500 dark:text-slate-400 mb-3" i18n="@@triage.runTriageDescription">
          Select a project and profile to run an on-demand triage analysis. Results will appear below.
        </p>
        <div class="flex flex-wrap items-end gap-4">
          <div class="flex flex-col gap-1">
            <label class="text-xs text-slate-500 dark:text-slate-400" i18n="@@triage.projectLabel">Project</label>
            <select
              class="rounded-md border border-slate-300 dark:border-slate-600 bg-white dark:bg-slate-700 text-sm px-3 py-1.5 text-slate-900 dark:text-white min-w-50 w-full"
              [ngModel]="selectedProjectId()"
              (ngModelChange)="selectedProjectId.set($event)">
              <option value="" disabled i18n="@@triage.selectProject">Select a project</option>
              @for (proj of projects(); track proj.id) {
                <option [value]="proj.id">{{ proj.name }}</option>
              }
            </select>
          </div>
          <div class="flex flex-col gap-1">
            <label class="text-xs text-slate-500 dark:text-slate-400" i18n="@@triage.profileLabelRun">Profile</label>
            <select
              class="rounded-md border border-slate-300 dark:border-slate-600 bg-white dark:bg-slate-700 text-sm px-3 py-1.5 text-slate-900 dark:text-white min-w-37.5"
              [ngModel]="selectedProfile()"
              (ngModelChange)="selectedProfile.set($event)">
              @for (p of profiles(); track p.name) {
                <option [value]="p.name">{{ p.name }}</option>
              }
            </select>
          </div>
          <button
            class="inline-flex items-center gap-2 px-4 py-1.5 text-sm font-medium rounded-md bg-indigo-600 text-white hover:bg-indigo-700 disabled:opacity-50 disabled:cursor-not-allowed"
            [disabled]="!selectedProjectId() || triageRunning()"
            (click)="runTriage()">
            @if (triageRunning()) {
              <span class="animate-spin inline-block h-4 w-4 border-2 border-white border-t-transparent rounded-full"></span>
            }
            <span i18n="@@triage.runButton">Run Triage</span>
          </button>
        </div>
      </section>

      <!-- Triage Results Table (shown only after running triage) -->
      @if (results().length > 0) {
        <section class="bg-white dark:bg-slate-800 rounded-lg shadow overflow-hidden mb-6">
          <div class="px-4 py-3 border-b border-slate-200 dark:border-slate-700 flex items-center justify-between">
            <h2 class="text-sm font-semibold text-slate-700 dark:text-slate-200" i18n="@@triage.resultsTitle">Triage Results</h2>
            <span class="text-xs text-slate-500 dark:text-slate-400">
              {{ results().length }} vulnerabilities
            </span>
          </div>
          <div class="overflow-x-auto">
            <table class="w-full text-sm text-left">
              <thead>
                <tr class="text-xs text-slate-500 dark:text-slate-400 border-b border-slate-200 dark:border-slate-700">
                  <th class="px-4 py-2 whitespace-nowrap font-medium cursor-pointer hover:text-slate-700 dark:hover:text-slate-200" (click)="sortBy('vulnerability_id')" i18n="@@triage.colId">Vulnerability</th>
                  <th class="px-4 py-2 whitespace-nowrap font-medium cursor-pointer hover:text-slate-700 dark:hover:text-slate-200" (click)="sortBy('priority_level')" i18n="@@triage.colPriority">Priority</th>
                  <th class="px-4 py-2 whitespace-nowrap font-medium cursor-pointer hover:text-slate-700 dark:hover:text-slate-200" (click)="sortBy('composite_score')" i18n="@@triage.colScore">Score</th>
                  <th class="px-4 py-2 whitespace-nowrap font-medium" i18n="@@triage.colSSVC">SSVC</th>
                  <th class="px-4 py-2 whitespace-nowrap font-medium" i18n="@@triage.colRationale">Rationale</th>
                </tr>
              </thead>
              <tbody>
                @for (result of results(); track result.vulnerability_id) {
                  <tr class="border-b border-slate-100 dark:border-slate-700/50 hover:bg-slate-50 dark:hover:bg-slate-700/30">
                    <td class="px-4 py-2 whitespace-nowrap">
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
                }
              </tbody>
            </table>
          </div>
        </section>
      }

      <!-- Quick links -->
      <div class="flex gap-3">
        <a routerLink="/triage/overview"
           class="inline-flex items-center px-3 py-2 text-sm font-medium rounded-md bg-indigo-50 dark:bg-indigo-900/30 text-indigo-700 dark:text-indigo-300 hover:bg-indigo-100 dark:hover:bg-indigo-900/50"
           i18n="@@triage.viewOverview">Cross-Project Overview</a>
        <a routerLink="/triage/paths"
           class="inline-flex items-center px-3 py-2 text-sm font-medium rounded-md bg-indigo-50 dark:bg-indigo-900/30 text-indigo-700 dark:text-indigo-300 hover:bg-indigo-100 dark:hover:bg-indigo-900/50"
           i18n="@@triage.viewPaths">Triage Paths</a>
        <a routerLink="/triage/profiles"
           class="inline-flex items-center px-3 py-2 text-sm font-medium rounded-md bg-indigo-50 dark:bg-indigo-900/30 text-indigo-700 dark:text-indigo-300 hover:bg-indigo-100 dark:hover:bg-indigo-900/50"
           i18n="@@triage.viewProfiles">Profiles</a>
      </div>
    }
  `,
})
export class TriageDashboardComponent implements OnInit {
  private readonly triageService = inject(TriageService);
  private readonly sbomService = inject(SbomService);

  readonly loading = signal(true);
  readonly overviewSummary = signal<TriageOverviewSummary | null>(null);
  readonly topRisks = signal<CrossProjectTriageResult[]>([]);
  readonly results = signal<TriageResult[]>([]);
  readonly profiles = signal<TriageProfile[]>([]);
  readonly selectedProfile = signal<string>('default');
  readonly projects = signal<SBOMProject[]>([]);
  readonly selectedProjectId = signal<string>('');
  readonly triageRunning = signal(false);

  private sortField: string = 'priority_level';
  private sortAsc = false;

  ngOnInit(): void {
    this.loadData();
  }

  private loadData(): void {
    // Load cross-project overview summary (provides immediate value on page load)
    this.triageService.getOverviewSummary().subscribe({
      next: (s) => {
        this.overviewSummary.set(s);
        this.loading.set(false);
      },
      error: () => this.loading.set(false),
    });

    // Load top risks across all projects (limit to 5 for dashboard)
    this.triageService.getOverviewVulnerabilities({ limit: 5, sort: 'priority' }).subscribe({
      next: (v) => this.topRisks.set(Array.isArray(v) ? v : []),
      error: () => {},
    });

    this.triageService.listProfiles().subscribe({
      next: (p) => this.profiles.set(Array.isArray(p) ? p : []),
      error: () => {},
    });

    this.sbomService.listProjects().subscribe({
      next: (p) => this.projects.set(Array.isArray(p) ? p : []),
      error: () => {},
    });
  }

  runTriageForProject(project: SBOMProject): void {
    this.selectedProjectId.set(String(project.id));
    this.runTriage();
  }

  runTriage(): void {
    const projectId = this.selectedProjectId();
    if (!projectId) return;

    this.triageRunning.set(true);
    this.triageService.getProjectTriage(projectId, { profile: this.selectedProfile() }).subscribe({
      next: (r) => {
        const results = Array.isArray(r) ? r : ((r as any)?.results ?? []);
        this.results.set(results);
        this.triageRunning.set(false);
      },
      error: () => this.triageRunning.set(false),
    });
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

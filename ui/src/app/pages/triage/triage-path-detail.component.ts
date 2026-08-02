import { Component, inject, type OnInit, signal } from '@angular/core';
import { ActivatedRoute, RouterLink } from '@angular/router';
import type { TriagePath } from '../../models/triage.model';
import { TriageService } from '../../services/triage.service';

@Component({
  selector: 'app-triage-path-detail',
  standalone: true,
  imports: [RouterLink],
  template: `
    @if (loading()) {
      <div class="flex items-center justify-center h-64">
        <div class="animate-spin rounded-full h-12 w-12 border-b-2 border-indigo-500"></div>
      </div>
    } @else if (path()) {
      <!-- Header -->
      <div class="flex items-center justify-between mb-6">
        <div>
          <h1 class="text-xl font-bold text-slate-900 dark:text-white" i18n="@@triagePathDetail.title">Triage Path Detail</h1>
          <p class="text-sm text-slate-500 dark:text-slate-400 mt-1 font-mono break-all">{{ path()!.action.package_name }}</p>
        </div>
      </div>

      <!-- Action Summary -->
      <section class="bg-white dark:bg-slate-800 rounded-lg shadow p-4 mb-6">
        <h2 class="text-sm font-semibold text-slate-700 dark:text-slate-200 mb-3" i18n="@@triagePathDetail.actionTitle">Remediation Action</h2>
        <div class="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
          <div>
            <p class="text-xs text-slate-500 dark:text-slate-400" i18n="@@triagePathDetail.type">Type</p>
            <p class="text-sm font-medium text-slate-900 dark:text-white">{{ path()!.action.type }}</p>
          </div>
          <div>
            <p class="text-xs text-slate-500 dark:text-slate-400" i18n="@@triagePathDetail.package">Package</p>
            <p class="text-sm font-medium font-mono text-slate-900 dark:text-white break-all">{{ path()!.action.package_name }}</p>
          </div>
          <div>
            <p class="text-xs text-slate-500 dark:text-slate-400" i18n="@@triagePathDetail.version">Version Change</p>
            <p class="text-sm font-medium font-mono text-slate-900 dark:text-white break-all">
              {{ path()!.action.current_version }} &rarr; {{ path()!.action.target_version }}
            </p>
          </div>
          <div>
            <p class="text-xs text-slate-500 dark:text-slate-400" i18n="@@triagePathDetail.ecosystem">Ecosystem</p>
            <p class="text-sm font-medium text-slate-900 dark:text-white">{{ path()!.action.ecosystem }}</p>
          </div>
        </div>
      </section>

      <!-- Stats -->
      <section class="grid grid-cols-2 sm:grid-cols-4 gap-4 mb-6">
        <div class="bg-white dark:bg-slate-800 rounded-lg shadow p-4">
          <p class="text-xs text-slate-500 dark:text-slate-400" i18n="@@triagePathDetail.impactScore">Impact Score</p>
          <p class="text-2xl font-bold text-indigo-600 dark:text-indigo-400 mt-1">{{ path()!.impact_score.toFixed(3) }}</p>
        </div>
        <div class="bg-white dark:bg-slate-800 rounded-lg shadow p-4">
          <p class="text-xs text-slate-500 dark:text-slate-400" i18n="@@triagePathDetail.maxPriority">Max Priority</p>
          <p class="text-2xl font-bold mt-1">
            <span [class]="priorityBadgeClass(path()!.max_priority_level)">{{ path()!.max_priority_level }}</span>
          </p>
        </div>
        <div class="bg-white dark:bg-slate-800 rounded-lg shadow p-4">
          <p class="text-xs text-slate-500 dark:text-slate-400" i18n="@@triagePathDetail.vulnCount">Resolved CVEs</p>
          <p class="text-2xl font-bold text-slate-900 dark:text-white mt-1">{{ path()!.total_vuln_count }}</p>
        </div>
        <div class="bg-white dark:bg-slate-800 rounded-lg shadow p-4">
          <p class="text-xs text-slate-500 dark:text-slate-400" i18n="@@triagePathDetail.serverCount">Affected Servers</p>
          <p class="text-2xl font-bold text-slate-900 dark:text-white mt-1">{{ path()!.total_server_count }}</p>
        </div>
      </section>

      <!-- Resolved Vulnerabilities -->
      <section class="bg-white dark:bg-slate-800 rounded-lg shadow overflow-hidden mb-6">
        <div class="px-4 py-3 border-b border-slate-200 dark:border-slate-700">
          <h2 class="text-sm font-semibold text-slate-700 dark:text-slate-200" i18n="@@triagePathDetail.resolvedTitle">Resolved Vulnerabilities</h2>
        </div>
        <div class="overflow-x-auto">
          <table class="w-full text-sm text-left">
            <thead>
              <tr class="text-xs text-slate-500 dark:text-slate-400 border-b border-slate-200 dark:border-slate-700">
                <th class="px-4 py-2 font-medium whitespace-nowrap" i18n="@@triagePathDetail.colId">Vulnerability</th>
                <th class="px-4 py-2 font-medium whitespace-nowrap" i18n="@@triagePathDetail.colPriority">Priority</th>
                <th class="px-4 py-2 font-medium whitespace-nowrap" i18n="@@triagePathDetail.colScore">Score</th>
                <th class="px-4 py-2 font-medium whitespace-nowrap" i18n="@@triagePathDetail.colFixed">Fixed In</th>
              </tr>
            </thead>
            <tbody>
              @for (vuln of path()!.resolved_vulnerabilities; track vuln.vulnerability_id) {
                <tr class="border-b border-slate-100 dark:border-slate-700/50">
                  <td class="px-4 py-2 whitespace-nowrap">
                    <a [routerLink]="['/vulnerabilities', vuln.vulnerability_id]"
                       class="text-indigo-600 dark:text-indigo-400 hover:underline font-mono text-xs">
                      {{ vuln.vulnerability_id }}
                    </a>
                  </td>
                  <td class="px-4 py-2 whitespace-nowrap">
                    <span [class]="priorityBadgeClass(vuln.priority_level)">{{ vuln.priority_level }}</span>
                  </td>
                  <td class="px-4 py-2 whitespace-nowrap font-mono text-xs text-slate-700 dark:text-slate-200">
                    {{ (vuln.composite_score * 100).toFixed(1) }}%
                  </td>
                  <td class="px-4 py-2 whitespace-nowrap font-mono text-xs text-slate-600 dark:text-slate-300">
                    {{ vuln.fixed_version }}
                  </td>
                </tr>
              } @empty {
                <tr>
                  <td colspan="4" class="px-4 py-4 text-center text-sm text-slate-500 dark:text-slate-400">No vulnerabilities.</td>
                </tr>
              }
            </tbody>
          </table>
        </div>
      </section>

      <!-- Affected Servers -->
      <section class="bg-white dark:bg-slate-800 rounded-lg shadow overflow-hidden">
        <div class="px-4 py-3 border-b border-slate-200 dark:border-slate-700">
          <h2 class="text-sm font-semibold text-slate-700 dark:text-slate-200" i18n="@@triagePathDetail.serversTitle">Affected Servers</h2>
        </div>
        <div class="px-4 py-3">
          <div class="flex flex-wrap gap-2">
            @for (server of path()!.affected_servers; track server) {
              <span class="inline-block px-2 py-1 rounded bg-slate-100 dark:bg-slate-700 text-xs font-mono text-slate-700 dark:text-slate-300">
                {{ server }}
              </span>
            } @empty {
              <p class="text-sm text-slate-500 dark:text-slate-400">No affected servers.</p>
            }
          </div>
        </div>
      </section>
    } @else {
      <div class="flex items-center justify-center h-64">
        <p class="text-sm text-slate-500 dark:text-slate-400" i18n="@@triagePathDetail.notFound">Triage path not found.</p>
      </div>
    }
  `,
})
export class TriagePathDetailComponent implements OnInit {
  private readonly triageService = inject(TriageService);
  private readonly route = inject(ActivatedRoute);

  readonly loading = signal(true);
  readonly path = signal<TriagePath | null>(null);

  ngOnInit(): void {
    const id = this.route.snapshot.paramMap.get('id');
    if (id) {
      this.triageService.getPath(id).subscribe({
        next: (p) => {
          this.path.set(p);
          this.loading.set(false);
        },
        error: () => {
          this.path.set(null);
          this.loading.set(false);
        },
      });
    } else {
      this.loading.set(false);
    }
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

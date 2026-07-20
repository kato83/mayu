import { Component, inject, OnInit, signal, DestroyRef } from '@angular/core';
import { Router, ActivatedRoute } from '@angular/router';
import { takeUntilDestroyed } from '@angular/core/rxjs-interop';
import { FormsModule } from '@angular/forms';
import { DatePipe } from '@angular/common';
import { Subject, debounceTime, distinctUntilChanged } from 'rxjs';

import { VulnerabilityService } from '../../services/vulnerability.service';
import { Vulnerability, SearchResponse } from '../../models/vulnerability.model';
import { SearchParams } from '../../models/search-params.model';
import { PaginationComponent } from '../../shared/pagination/pagination.component';

/** Available ecosystems for the dropdown filter. */
const ECOSYSTEMS = [
  'Go', 'npm', 'PyPI', 'Maven', 'crates.io', 'NuGet', 'Packagist',
  'RubyGems', 'Hex', 'Pub', 'SwiftURL', 'ConanCenter', 'Hackage',
  'CRAN', 'Bioconductor', 'AlmaLinux', 'Alpine', 'Chainguard',
  'Debian', 'Rocky Linux', 'Ubuntu', 'Wolfi', 'Android', 'Linux',
];

const SEVERITIES = ['critical', 'high', 'medium', 'low', 'none'] as const;

interface FilterState {
  id: string;
  package: string;
  ecosystem: string;
  alias: string;
  purl: string;
  severity: string;
  since: string;
  version: string;
}

function emptyFilters(): FilterState {
  return { id: '', package: '', ecosystem: '', alias: '', purl: '', severity: '', since: '', version: '' };
}

@Component({
  selector: 'app-vulnerabilities',
  standalone: true,
  imports: [PaginationComponent, FormsModule, DatePipe],
  template: `
    <div class="space-y-4">
      <!-- Filter panel -->
      <div class="rounded-lg border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-800 p-4 shadow-sm">
        <div class="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3">
          <!-- ID filter -->
          <div>
            <label for="filter-id" class="block text-xs font-medium text-slate-600 dark:text-slate-400 mb-1" i18n="@@vulnList.filterId">ID</label>
            <input
              id="filter-id"
              type="text"
              [ngModel]="filters.id"
              (ngModelChange)="onFilterChange('id', $event)"
              placeholder="CVE-2024-..."
              i18n-placeholder="@@vulnList.filterIdPlaceholder"
              class="w-full rounded-md border border-slate-300 dark:border-slate-600 dark:bg-slate-700 dark:text-slate-200 px-3 py-1.5 text-sm focus:border-indigo-500 focus:ring-1 focus:ring-indigo-500 outline-none"
            />
          </div>

          <!-- Package filter -->
          <div>
            <label for="filter-package" class="block text-xs font-medium text-slate-600 dark:text-slate-400 mb-1" i18n="@@vulnList.filterPackage">Package</label>
            <input
              id="filter-package"
              type="text"
              [ngModel]="filters.package"
              (ngModelChange)="onFilterChange('package', $event)"
              placeholder="golang.org/x/crypto"
              i18n-placeholder="@@vulnList.filterPackagePlaceholder"
              class="w-full rounded-md border border-slate-300 dark:border-slate-600 dark:bg-slate-700 dark:text-slate-200 px-3 py-1.5 text-sm focus:border-indigo-500 focus:ring-1 focus:ring-indigo-500 outline-none"
            />
          </div>

          <!-- Ecosystem filter -->
          <div>
            <label for="filter-ecosystem" class="block text-xs font-medium text-slate-600 dark:text-slate-400 mb-1" i18n="@@vulnList.filterEcosystem">Ecosystem</label>
            <select
              id="filter-ecosystem"
              [ngModel]="filters.ecosystem"
              (ngModelChange)="onFilterChange('ecosystem', $event)"
              class="w-full rounded-md border border-slate-300 dark:border-slate-600 dark:bg-slate-700 dark:text-slate-200 px-3 py-1.5 text-sm focus:border-indigo-500 focus:ring-1 focus:ring-indigo-500 outline-none"
            >
              <option value="" i18n="@@vulnList.allEcosystems">All ecosystems</option>
              @for (eco of ecosystems; track eco) {
                <option [value]="eco">{{ eco }}</option>
              }
            </select>
          </div>

          <!-- Severity filter -->
          <div>
            <label for="filter-severity" class="block text-xs font-medium text-slate-600 dark:text-slate-400 mb-1" i18n="@@vulnList.filterSeverity">Severity</label>
            <select
              id="filter-severity"
              [ngModel]="filters.severity"
              (ngModelChange)="onFilterChange('severity', $event)"
              class="w-full rounded-md border border-slate-300 dark:border-slate-600 dark:bg-slate-700 dark:text-slate-200 px-3 py-1.5 text-sm focus:border-indigo-500 focus:ring-1 focus:ring-indigo-500 outline-none"
            >
              <option value="" i18n="@@vulnList.allSeverities">All severities</option>
              @for (sev of severities; track sev) {
                <option [value]="sev">{{ sev }}</option>
              }
            </select>
          </div>

          <!-- Alias filter -->
          <div>
            <label for="filter-alias" class="block text-xs font-medium text-slate-600 dark:text-slate-400 mb-1" i18n="@@vulnList.filterAlias">Alias</label>
            <input
              id="filter-alias"
              type="text"
              [ngModel]="filters.alias"
              (ngModelChange)="onFilterChange('alias', $event)"
              placeholder="GHSA-xxxx..."
              i18n-placeholder="@@vulnList.filterAliasPlaceholder"
              class="w-full rounded-md border border-slate-300 dark:border-slate-600 dark:bg-slate-700 dark:text-slate-200 px-3 py-1.5 text-sm focus:border-indigo-500 focus:ring-1 focus:ring-indigo-500 outline-none"
            />
          </div>

          <!-- Purl filter -->
          <div>
            <label for="filter-purl" class="block text-xs font-medium text-slate-600 dark:text-slate-400 mb-1" i18n="@@vulnList.filterPurl">Package URL</label>
            <input
              id="filter-purl"
              type="text"
              [ngModel]="filters.purl"
              (ngModelChange)="onFilterChange('purl', $event)"
              placeholder="pkg:golang/..."
              i18n-placeholder="@@vulnList.filterPurlPlaceholder"
              class="w-full rounded-md border border-slate-300 dark:border-slate-600 dark:bg-slate-700 dark:text-slate-200 px-3 py-1.5 text-sm focus:border-indigo-500 focus:ring-1 focus:ring-indigo-500 outline-none"
            />
          </div>

          <!-- Version filter -->
          <div>
            <label for="filter-version" class="block text-xs font-medium text-slate-600 dark:text-slate-400 mb-1" i18n="@@vulnList.filterVersion">Version</label>
            <input
              id="filter-version"
              type="text"
              [ngModel]="filters.version"
              (ngModelChange)="onFilterChange('version', $event)"
              placeholder="0.17.0"
              i18n-placeholder="@@vulnList.filterVersionPlaceholder"
              class="w-full rounded-md border border-slate-300 dark:border-slate-600 dark:bg-slate-700 dark:text-slate-200 px-3 py-1.5 text-sm focus:border-indigo-500 focus:ring-1 focus:ring-indigo-500 outline-none"
            />
          </div>

          <!-- Since filter -->
          <div>
            <label for="filter-since" class="block text-xs font-medium text-slate-600 dark:text-slate-400 mb-1" i18n="@@vulnList.filterSince">Modified since</label>
            <input
              id="filter-since"
              type="date"
              [ngModel]="filters.since"
              (ngModelChange)="onFilterChange('since', $event)"
              class="w-full rounded-md border border-slate-300 dark:border-slate-600 dark:bg-slate-700 dark:text-slate-200 px-3 py-1.5 text-sm focus:border-indigo-500 focus:ring-1 focus:ring-indigo-500 outline-none"
            />
          </div>
        </div>

        <!-- Clear button -->
        <div class="mt-3 flex justify-end">
          <button
            (click)="clearFilters()"
            class="px-3 py-1.5 text-xs font-medium text-slate-600 dark:text-slate-300 hover:text-slate-800 dark:hover:text-white hover:bg-slate-100 dark:hover:bg-slate-700 rounded-md transition-colors"
            i18n="@@vulnList.clearFilters"
          >
            Clear filters
          </button>
        </div>
      </div>

      <!-- Loading state -->
      @if (loading()) {
        <div class="flex items-center justify-center py-12">
          <div class="text-slate-500" i18n="@@vulnList.loading">Loading vulnerabilities...</div>
        </div>
      }

      <!-- Error state -->
      @if (error()) {
        <div class="rounded-md bg-red-50 border border-red-200 p-4">
          <p class="text-sm text-red-700">{{ error() }}</p>
        </div>
      }

      <!-- Data table -->
      @if (!loading() && !error()) {
        @if (vulnerabilities().length === 0) {
          <div class="text-center py-12">
            <div class="text-4xl mb-3">🔍</div>
            <p class="text-slate-500 dark:text-slate-400" i18n="@@vulnList.empty">No vulnerabilities found.</p>
            <p class="text-sm text-slate-400 dark:text-slate-500 mt-1" i18n="@@vulnList.emptyHint">Try adjusting your filters.</p>
          </div>
        } @else {
          <div class="overflow-x-auto rounded-lg border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-800 shadow-sm">
            <table class="min-w-full divide-y divide-slate-200 dark:divide-slate-700">
              <thead class="bg-slate-50 dark:bg-slate-800/50">
                <tr>
                  <th class="px-4 py-3 text-left text-xs font-medium text-slate-500 dark:text-slate-400 uppercase tracking-wider" i18n="@@vulnList.colId">ID</th>
                  <th class="px-4 py-3 text-left text-xs font-medium text-slate-500 dark:text-slate-400 uppercase tracking-wider" i18n="@@vulnList.colSummary">Summary</th>
                  <th class="px-4 py-3 text-left text-xs font-medium text-slate-500 dark:text-slate-400 uppercase tracking-wider" i18n="@@vulnList.colEcosystem">Ecosystem</th>
                  <th class="px-4 py-3 text-left text-xs font-medium text-slate-500 dark:text-slate-400 uppercase tracking-wider" i18n="@@vulnList.colSeverity">Severity</th>
                  <th class="px-4 py-3 text-left text-xs font-medium text-slate-500 dark:text-slate-400 uppercase tracking-wider" i18n="@@vulnList.colModified">Modified</th>
                </tr>
              </thead>
              <tbody class="divide-y divide-slate-200 dark:divide-slate-700">
                @for (vuln of vulnerabilities(); track vuln.id) {
                  <tr
                    class="hover:bg-slate-50 dark:hover:bg-slate-700/50 cursor-pointer transition-colors"
                    (click)="navigateToDetail(vuln.id)"
                  >
                    <td class="px-4 py-3 text-sm font-medium text-indigo-600 dark:text-indigo-400 whitespace-nowrap">
                      {{ vuln.id }}
                    </td>
                    <td class="px-4 py-3 text-sm text-slate-700 dark:text-slate-300 max-w-md truncate">
                      {{ vuln.summary || '—' }}
                    </td>
                    <td class="px-4 py-3 text-sm text-slate-600 dark:text-slate-400 whitespace-nowrap">
                      {{ getEcosystem(vuln) }}
                    </td>
                    <td class="px-4 py-3 whitespace-nowrap">
                      @if (getSeverityLabel(vuln); as severity) {
                        <span [class]="getSeverityClasses(severity)">
                          {{ severity }}
                        </span>
                      } @else {
                        <span class="text-sm text-slate-400">—</span>
                      }
                    </td>
                    <td class="px-4 py-3 text-sm text-slate-500 dark:text-slate-400 whitespace-nowrap">
                      {{ vuln.modified | date:'yyyy-MM-dd' }}
                    </td>
                  </tr>
                }
              </tbody>
            </table>
          </div>

          <!-- Pagination -->
          <app-pagination
            [total]="total()"
            [limit]="limit()"
            [offset]="offset()"
            (offsetChange)="onOffsetChange($event)"
          />
        }
      }
    </div>
  `,
})
export class VulnerabilitiesComponent implements OnInit {
  private readonly vulnService = inject(VulnerabilityService);
  private readonly router = inject(Router);
  private readonly route = inject(ActivatedRoute);
  private readonly destroyRef = inject(DestroyRef);

  readonly ecosystems = ECOSYSTEMS;
  readonly severities = SEVERITIES;

  readonly vulnerabilities = signal<Vulnerability[]>([]);
  readonly total = signal(0);
  readonly limit = signal(20);
  readonly offset = signal(0);
  readonly loading = signal(false);
  readonly error = signal<string | null>(null);

  filters: FilterState = emptyFilters();

  private readonly filterChange$ = new Subject<void>();
  private initialLoad = true;

  ngOnInit(): void {
    // Debounced filter changes trigger search
    this.filterChange$
      .pipe(
        debounceTime(300),
        takeUntilDestroyed(this.destroyRef),
      )
      .subscribe(() => {
        this.offset.set(0);
        this.syncUrlAndLoad();
      });

    // Initialize from URL query params
    this.route.queryParams
      .pipe(takeUntilDestroyed(this.destroyRef))
      .subscribe((params) => {
        if (this.initialLoad) {
          // Restore filters from URL
          this.filters = {
            id: params['id'] || '',
            package: params['package'] || '',
            ecosystem: params['ecosystem'] || '',
            alias: params['alias'] || '',
            purl: params['purl'] || '',
            severity: params['severity'] || '',
            since: params['since'] || '',
            version: params['version'] || '',
          } as FilterState;

          const limit = params['limit'] ? parseInt(params['limit'], 10) : 20;
          const offset = params['offset'] ? parseInt(params['offset'], 10) : 0;
          this.limit.set(limit);
          this.offset.set(offset);
          this.initialLoad = false;
          this.loadData();
        }
      });
  }

  onFilterChange(key: keyof FilterState, value: string): void {
    this.filters = { ...this.filters, [key]: value };
    this.filterChange$.next();
  }

  clearFilters(): void {
    this.filters = emptyFilters();
    this.offset.set(0);
    this.syncUrlAndLoad();
  }

  onOffsetChange(newOffset: number): void {
    this.offset.set(newOffset);
    this.syncUrlAndLoad();
  }

  navigateToDetail(id: string): void {
    this.router.navigate(['/vulnerabilities', id]);
  }

  getEcosystem(vuln: Vulnerability): string {
    if (vuln.affected && vuln.affected.length > 0 && vuln.affected[0].package) {
      return vuln.affected[0].package.ecosystem;
    }
    return '—';
  }

  getSeverityLabel(vuln: Vulnerability): string | null {
    if (vuln.severity && vuln.severity.length > 0) {
      const score = this.extractBaseScore(vuln.severity[0].score);
      if (score !== null) {
        return this.scoreToLabel(score);
      }
    }
    if (vuln.affected) {
      for (const affected of vuln.affected) {
        if (affected.severity && affected.severity.length > 0) {
          const score = this.extractBaseScore(affected.severity[0].score);
          if (score !== null) {
            return this.scoreToLabel(score);
          }
        }
      }
    }
    return null;
  }

  getSeverityClasses(severity: string): string {
    const base = 'inline-flex items-center px-2 py-0.5 rounded text-xs font-medium';
    switch (severity.toLowerCase()) {
      case 'critical':
        return `${base} bg-red-100 text-red-800`;
      case 'high':
        return `${base} bg-orange-100 text-orange-800`;
      case 'medium':
        return `${base} bg-yellow-100 text-yellow-800`;
      case 'low':
        return `${base} bg-blue-100 text-blue-800`;
      default:
        return `${base} bg-slate-100 text-slate-800`;
    }
  }

  private syncUrlAndLoad(): void {
    const queryParams: Record<string, string | number | null> = {};

    // Add non-empty filters to URL
    const filterKeys: (keyof FilterState)[] = ['id', 'package', 'ecosystem', 'alias', 'purl', 'severity', 'since', 'version'];
    for (const key of filterKeys) {
      queryParams[key] = this.filters[key] || null;
    }
    queryParams['limit'] = this.limit();
    queryParams['offset'] = this.offset() > 0 ? this.offset() : null;

    this.router.navigate([], {
      relativeTo: this.route,
      queryParams,
      replaceUrl: true,
    });

    this.loadData();
  }

  private loadData(): void {
    this.loading.set(true);
    this.error.set(null);

    const params: SearchParams = {
      limit: this.limit(),
      offset: this.offset(),
      fields: 'id,summary,modified,severity,ecosystem',
    };

    // Apply filters
    if (this.filters.id) params.id = this.filters.id;
    if (this.filters.package) params.package = this.filters.package;
    if (this.filters.ecosystem) params.ecosystem = this.filters.ecosystem;
    if (this.filters.alias) params.alias = this.filters.alias;
    if (this.filters.purl) params.purl = this.filters.purl;
    if (this.filters.severity) params.severity = this.filters.severity as SearchParams['severity'];
    if (this.filters.since) params.since = this.filters.since;
    if (this.filters.version) params.version = this.filters.version;

    this.vulnService.search(params)
      .pipe(takeUntilDestroyed(this.destroyRef))
      .subscribe({
        next: (response: SearchResponse) => {
          this.vulnerabilities.set(response.vulnerabilities);
          this.total.set(response.total);
          this.loading.set(false);
        },
        error: (err) => {
          this.error.set(err.error?.error || 'Failed to load vulnerabilities');
          this.loading.set(false);
        },
      });
  }

  private extractBaseScore(vectorOrScore: string): number | null {
    if (vectorOrScore.startsWith('CVSS:3')) {
      return this.computeCvss3BaseScore(vectorOrScore);
    }
    if (vectorOrScore.startsWith('CVSS:')) {
      // CVSS v4 or unknown — not yet supported
      return null;
    }
    const num = parseFloat(vectorOrScore);
    return isNaN(num) ? null : num;
  }

  /**
   * Compute CVSS v3.x base score from a vector string.
   * Implements the CVSS 3.0/3.1 specification formula.
   */
  private computeCvss3BaseScore(vector: string): number | null {
    const metrics = new Map<string, string>();
    const parts = vector.split('/');
    for (const part of parts) {
      const [key, val] = part.split(':');
      if (key && val) metrics.set(key, val);
    }

    const AV = metrics.get('AV');
    const AC = metrics.get('AC');
    const PR = metrics.get('PR');
    const UI = metrics.get('UI');
    const S = metrics.get('S');
    const C = metrics.get('C');
    const I = metrics.get('I');
    const A = metrics.get('A');
    if (!AV || !AC || !PR || !UI || !S || !C || !I || !A) return null;

    const avMap: Record<string, number> = { N: 0.85, A: 0.62, L: 0.55, P: 0.20 };
    const acMap: Record<string, number> = { L: 0.77, H: 0.44 };
    const prMapU: Record<string, number> = { N: 0.85, L: 0.62, H: 0.27 };
    const prMapC: Record<string, number> = { N: 0.85, L: 0.68, H: 0.50 };
    const uiMap: Record<string, number> = { N: 0.85, R: 0.62 };
    const ciaMap: Record<string, number> = { H: 0.56, L: 0.22, N: 0 };

    const av = avMap[AV];
    const ac = acMap[AC];
    const scopeChanged = S === 'C';
    const pr = scopeChanged ? prMapC[PR] : prMapU[PR];
    const ui = uiMap[UI];
    const c = ciaMap[C];
    const i = ciaMap[I];
    const a = ciaMap[A];

    if (av == null || ac == null || pr == null || ui == null || c == null || i == null || a == null) return null;

    const iss = 1 - (1 - c) * (1 - i) * (1 - a);
    const impact = scopeChanged
      ? 7.52 * (iss - 0.029) - 3.25 * Math.pow(iss - 0.02, 15)
      : 6.42 * iss;

    if (impact <= 0) return 0;

    const exploitability = 8.22 * av * ac * pr * ui;
    const raw = scopeChanged
      ? 1.08 * (impact + exploitability)
      : impact + exploitability;

    return Math.min(Math.ceil(raw * 10) / 10, 10.0);
  }

  private scoreToLabel(score: number): string {
    if (score >= 9.0) return 'Critical';
    if (score >= 7.0) return 'High';
    if (score >= 4.0) return 'Medium';
    if (score > 0.0) return 'Low';
    return 'None';
  }
}

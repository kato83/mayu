import { Component, inject, OnInit, signal, DestroyRef } from '@angular/core';
import { Router, ActivatedRoute } from '@angular/router';
import { takeUntilDestroyed } from '@angular/core/rxjs-interop';
import { FormsModule } from '@angular/forms';
import { DatePipe, UpperCasePipe } from '@angular/common';
import { Subject, debounceTime } from 'rxjs';

import { VulnerabilityService } from '../../services/vulnerability.service';
import { Vulnerability, SearchResponse } from '../../models/vulnerability.model';
import { SearchParams } from '../../models/search-params.model';
import { PaginationComponent, PageChangeEvent } from '../../shared/pagination/pagination.component';

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
  severity: string;
  since: string;
  version: string;
}

function emptyFilters(): FilterState {
  return { id: '', package: '', ecosystem: '', severity: '', since: '', version: '' };
}

@Component({
  selector: 'app-vulnerabilities',
  standalone: true,
  imports: [PaginationComponent, FormsModule, DatePipe, UpperCasePipe],
  template: `
    <div class="space-y-4">
      <!-- Filter panel -->
      <div class="rounded-lg border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-800 p-4 shadow-sm">
        <div class="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3">
          <!-- ID filter -->
          <div>
            <label for="filter-id" class="block text-xs font-medium text-slate-600 dark:text-slate-400 mb-1" i18n="@@vulnList.filterId">ID / Alias</label>
            <input
              id="filter-id"
              type="text"
              [ngModel]="filters.id"
              (ngModelChange)="onFilterChange('id', $event)"
              placeholder="CVE-2024-..., GHSA-..."
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
              placeholder="golang.org/x/crypto, pkg:golang/..."
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
                <option [value]="sev">{{ sev | uppercase }}</option>
              }
            </select>
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
                      @if (getSeverityLabels(vuln); as labels) {
                        @if (labels.length === 1) {
                          <span [class]="getSeverityClasses(labels[0])">
                            {{ labels[0] | uppercase }}
                          </span>
                        } @else if (labels.length === 2) {
                          <span [class]="getSeverityClasses(labels[0])">
                            {{ labels[0] | uppercase }}
                          </span>
                          <span class="text-xs text-slate-500 dark:text-slate-400 mx-0.5">–</span>
                          <span [class]="getSeverityClasses(labels[1])">
                            {{ labels[1] | uppercase }}
                          </span>
                        }
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
            [page]="currentPage()"
            [hasNext]="hasNextPage()"
            [hasPrevious]="hasPreviousPage()"
            (pageChange)="onPageChange($event)"
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
  readonly currentPage = signal(1);
  readonly loading = signal(false);
  readonly error = signal<string | null>(null);

  /** Whether a next page is available (API returned next_cursor) */
  readonly hasNextPage = signal(false);
  /** Whether we can go back (cursor stack is non-empty) */
  readonly hasPreviousPage = signal(false);

  filters: FilterState = emptyFilters();

  /** Stack of cursors for previous pages. Index 0 = page 2's cursor, etc. */
  private cursorStack: string[] = [];
  /** The cursor for the current page (empty string = first page) */
  private currentCursor = '';
  /** The next_cursor returned by the last API response */
  private nextCursor = '';

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
        this.resetPagination();
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
            package: params['purl'] || params['package'] || '',
            ecosystem: params['ecosystem'] || '',
            severity: params['severity'] || '',
            since: params['since'] || '',
            version: params['version'] || '',
          };

          const limit = params['limit'] ? parseInt(params['limit'], 10) : 20;
          this.limit.set(limit);

          // Restore cursor from URL if present
          const cursor = params['cursor'] || '';
          this.currentCursor = cursor;

          // If cursor is present, we don't know the exact page number,
          // but we can infer it from the cursor stack (which is empty on initial load from URL).
          // For simplicity, if cursor is present, show page as "?" until we load.
          // After loading, we know current position from total/limit.

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
    this.resetPagination();
    this.syncUrlAndLoad();
  }

  onPageChange(event: PageChangeEvent): void {
    if (event.direction === 'next') {
      // Push current cursor to stack before moving forward
      this.cursorStack.push(this.currentCursor);
      this.currentCursor = this.nextCursor;
      this.currentPage.set(this.currentPage() + 1);
    } else if (event.direction === 'previous') {
      // Pop the previous cursor from stack
      this.currentCursor = this.cursorStack.pop() || '';
      this.currentPage.set(Math.max(1, this.currentPage() - 1));
    } else {
      // 'first'
      this.resetPagination();
    }
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

  getSeverityLabels(vuln: Vulnerability): string[] | null {
    if (vuln.severity && vuln.severity.length > 0) {
      const worst = this.toLabel(vuln.severity[0].score);
      if (worst) {
        if (vuln.severity.length >= 2) {
          const best = this.toLabel(vuln.severity[1].score);
          if (best && best !== worst) {
            return [worst, best];
          }
        }
        return [worst];
      }
    }
    if (vuln.affected) {
      for (const affected of vuln.affected) {
        if (affected.severity && affected.severity.length > 0) {
          const label = this.toLabel(affected.severity[0].score);
          if (label) {
            return [label];
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

  private resetPagination(): void {
    this.cursorStack = [];
    this.currentCursor = '';
    this.nextCursor = '';
    this.currentPage.set(1);
    this.hasNextPage.set(false);
    this.hasPreviousPage.set(false);
  }

  private syncUrlAndLoad(): void {
    const queryParams: Record<string, string | number | null> = {};

    // Add non-empty filters to URL
    const filterKeys: (keyof FilterState)[] = ['id', 'package', 'ecosystem', 'severity', 'since', 'version'];
    for (const key of filterKeys) {
      queryParams[key] = this.filters[key] || null;
    }
    queryParams['limit'] = this.limit();
    queryParams['cursor'] = this.currentCursor || null;
    // Remove legacy offset from URL
    queryParams['offset'] = null;

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
      fields: 'id,summary,modified,severity,ecosystem',
    };

    // Use cursor if available, otherwise first page (no cursor needed)
    if (this.currentCursor) {
      params.cursor = this.currentCursor;
    }

    // Apply filters
    if (this.filters.id) params.id = this.filters.id;
    if (this.filters.package) {
      if (this.filters.package.startsWith('pkg:')) {
        params.purl = this.filters.package;
      } else {
        params.package = this.filters.package;
      }
    }
    if (this.filters.ecosystem) params.ecosystem = this.filters.ecosystem;
    if (this.filters.severity) params.severity = this.filters.severity as SearchParams['severity'];
    if (this.filters.since) params.since = this.filters.since;
    if (this.filters.version) params.version = this.filters.version;

    this.vulnService.search(params)
      .pipe(takeUntilDestroyed(this.destroyRef))
      .subscribe({
        next: (response: SearchResponse) => {
          this.vulnerabilities.set(response.vulnerabilities);
          this.total.set(response.total);
          this.nextCursor = response.next_cursor || '';
          this.hasNextPage.set(!!this.nextCursor);
          this.hasPreviousPage.set(this.cursorStack.length > 0);
          this.loading.set(false);
        },
        error: (err) => {
          this.error.set(err.error?.error || 'Failed to load vulnerabilities');
          this.loading.set(false);
        },
      });
  }

  /**
   * Convert a severity score string to a display label.
   * Handles label strings (CRITICAL, HIGH, etc.) returned from the API.
   */
  private toLabel(scoreStr: string): string | null {
    const knownLabels: Record<string, string> = {
      critical: 'Critical',
      high: 'High',
      medium: 'Medium',
      low: 'Low',
      none: 'None',
    };
    const lower = scoreStr.toLowerCase();
    return knownLabels[lower] ?? null;
  }
}

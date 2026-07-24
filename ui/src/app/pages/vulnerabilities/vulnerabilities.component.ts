import { Component, inject, OnInit, signal, DestroyRef } from '@angular/core';
import { Router, ActivatedRoute, RouterLink } from '@angular/router';
import { takeUntilDestroyed } from '@angular/core/rxjs-interop';
import { FormsModule } from '@angular/forms';
import { DatePipe, UpperCasePipe } from '@angular/common';
import { Subject, debounceTime } from 'rxjs';

import { VulnerabilityService } from '../../services/vulnerability.service';
import { Vulnerability, SearchResponse } from '../../models/vulnerability.model';
import { SearchParams } from '../../models/search-params.model';
import { PaginationComponent, PageChangeEvent } from '../../shared/pagination/pagination.component';

const SEVERITIES = ['critical', 'high', 'medium', 'low', 'none', 'unknown'] as const;

interface FilterState {
  id: string;
  package: string;
  ecosystem: string;
  severity: string;
  since: string;
  version: string;
  kev: boolean;
  sort: string;
}

function emptyFilters(): FilterState {
  return { id: '', package: '', ecosystem: '', severity: '', since: '', version: '', kev: false, sort: 'modified_desc' };
}

@Component({
  selector: 'app-vulnerabilities',
  standalone: true,
  imports: [PaginationComponent, FormsModule, DatePipe, UpperCasePipe, RouterLink],
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
            <label for="filter-ecosystem" class="block text-xs font-medium text-slate-600 dark:text-slate-400 mb-1">
              <span i18n="@@vulnList.filterEcosystem">Ecosystem</span>
              <span class="font-normal text-slate-400 dark:text-slate-500" i18n="@@vulnList.filterEcosystemNote"> (OSV only)</span>
            </label>
            <select
              id="filter-ecosystem"
              [ngModel]="filters.ecosystem"
              (ngModelChange)="onFilterChange('ecosystem', $event)"
              class="w-full rounded-md border border-slate-300 dark:border-slate-600 dark:bg-slate-700 dark:text-slate-200 px-3 py-1.5 text-sm focus:border-indigo-500 focus:ring-1 focus:ring-indigo-500 outline-none"
            >
              <option value="" i18n="@@vulnList.allEcosystems">All ecosystems</option>
              @for (eco of ecosystems(); track eco) {
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

          <!-- KEV filter -->
          <div class="flex items-end">
            <label class="inline-flex items-center gap-2 cursor-pointer py-1.5">
              <input
                type="checkbox"
                [ngModel]="filters.kev"
                (ngModelChange)="onFilterChange('kev', $event)"
                class="rounded border-slate-300 dark:border-slate-600 text-indigo-600 focus:ring-indigo-500 h-4 w-4"
              />
              <span class="text-sm font-medium text-slate-700 dark:text-slate-300" i18n="@@vulnList.filterKev">KEV only</span>
            </label>
          </div>

          <!-- Sort -->
          <div>
            <label for="filter-sort" class="block text-xs font-medium text-slate-600 dark:text-slate-400 mb-1" i18n="@@vulnList.filterSort">Sort</label>
            <select
              id="filter-sort"
              [ngModel]="filters.sort"
              (ngModelChange)="onFilterChange('sort', $event)"
              class="w-full rounded-md border border-slate-300 dark:border-slate-600 dark:bg-slate-700 dark:text-slate-200 px-3 py-1.5 text-sm focus:border-indigo-500 focus:ring-1 focus:ring-indigo-500 outline-none"
            >
              <option value="modified_desc" i18n="@@vulnList.sortModifiedDesc">Modified (newest)</option>
              <option value="modified_asc" i18n="@@vulnList.sortModifiedAsc">Modified (oldest)</option>
              <option value="published_desc" i18n="@@vulnList.sortPublishedDesc">Published (newest)</option>
              <option value="published_asc" i18n="@@vulnList.sortPublishedAsc">Published (oldest)</option>
            </select>
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
                  <th class="px-4 py-3 text-left text-xs font-medium text-slate-500 dark:text-slate-400 uppercase tracking-wider">
                    @if (filters.sort.startsWith('published')) {
                      <span i18n="@@vulnList.colPublished">Published</span>
                    } @else {
                      <span i18n="@@vulnList.colModified">Modified</span>
                    }
                  </th>
                </tr>
              </thead>
              <tbody class="divide-y divide-slate-200 dark:divide-slate-700">
                @for (vuln of vulnerabilities(); track vuln.id) {
                  <tr
                    class="hover:bg-slate-50 dark:hover:bg-slate-700/50 transition-colors"
                  >
                    <td class="px-4 py-3 text-sm font-medium whitespace-nowrap">
                      <a [routerLink]="['/vulnerabilities', vuln.id]"
                         class="text-indigo-600 dark:text-indigo-400 hover:text-indigo-800 dark:hover:text-indigo-300 hover:underline">
                        {{ vuln.id }}
                      </a>
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
                      @if (filters.sort.startsWith('published')) {
                        {{ vuln.published | date:'yyyy-MM-dd' }}
                      } @else {
                        {{ vuln.modified | date:'yyyy-MM-dd' }}
                      }
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
            [nextQueryParams]="nextPageQueryParams()"
            [previousQueryParams]="previousPageQueryParams()"
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

  readonly ecosystems = signal<string[]>([]);
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
  private skipNextParamsChange = false;

  ngOnInit(): void {
    // Load ecosystems from API
    this.vulnService.getEcosystems()
      .pipe(takeUntilDestroyed(this.destroyRef))
      .subscribe((res) => {
        this.ecosystems.set(res.ecosystems);
      });

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
        // Skip if this change was triggered programmatically by syncUrlAndLoad
        if (this.skipNextParamsChange) {
          this.skipNextParamsChange = false;
          return;
        }

        // Restore filters from URL
        this.filters = {
          id: params['id'] || '',
          package: params['purl'] || params['package'] || '',
          ecosystem: params['ecosystem'] || '',
          severity: params['severity'] || '',
          since: params['since'] || '',
          version: params['version'] || '',
          kev: params['kev'] === 'true',
          sort: params['sort'] || 'modified_desc',
        };

        const limit = params['limit'] ? parseInt(params['limit'], 10) : 20;
        this.limit.set(limit);

        // Restore cursor from URL if present
        const cursor = params['cursor'] || '';
        this.currentCursor = cursor;

        // Restore page number from URL
        const page = params['page'] ? parseInt(params['page'], 10) : 1;
        this.currentPage.set(page);

        // If cursor is present, there's at least a first page to go back to
        if (cursor) {
          this.hasPreviousPage.set(true);
        } else {
          this.hasPreviousPage.set(false);
          this.cursorStack = [];
        }

        this.loadData();
      });
  }

  onFilterChange(key: keyof FilterState, value: string | boolean): void {
    this.filters = { ...this.filters, [key]: value };
    this.filterChange$.next();
  }

  clearFilters(): void {
    this.filters = emptyFilters();
    this.resetPagination();
    this.syncUrlAndLoad();
  }

  nextPageQueryParams(): Record<string, string | null> {
    const nextPage = this.currentPage() + 1;
    return { cursor: this.nextCursor || null, page: String(nextPage) };
  }

  previousPageQueryParams(): Record<string, string | null> {
    const prevCursor = this.cursorStack.length > 0
      ? this.cursorStack[this.cursorStack.length - 1]
      : null;
    const prevPage = Math.max(1, this.currentPage() - 1);
    return { cursor: prevCursor || null, page: prevPage > 1 ? String(prevPage) : null };
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
    const filterKeys = ['id', 'package', 'ecosystem', 'severity', 'since', 'version'] as const;
    for (const key of filterKeys) {
      queryParams[key] = this.filters[key] || null;
    }
    queryParams['kev'] = this.filters.kev ? 'true' : null;
    queryParams['sort'] = this.filters.sort !== 'modified_desc' ? this.filters.sort : null;
    queryParams['limit'] = this.limit();
    queryParams['cursor'] = this.currentCursor || null;
    queryParams['page'] = this.currentPage() > 1 ? this.currentPage() : null;
    // Remove legacy offset from URL
    queryParams['offset'] = null;

    // Flag to skip the next queryParams emission (since we're navigating programmatically)
    this.skipNextParamsChange = true;

    this.router.navigate([], {
      relativeTo: this.route,
      queryParams,
      replaceUrl: false,
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
    if (this.filters.kev) params.kev = true;
    if (this.filters.sort && this.filters.sort !== 'modified_desc') {
      params.sort = this.filters.sort as SearchParams['sort'];
    }

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

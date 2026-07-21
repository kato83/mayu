import { Component, computed, input, output } from '@angular/core';
import { RouterLink } from '@angular/router';

/**
 * Pagination event emitted when the user navigates pages.
 * In cursor-based mode, `cursor` indicates the target cursor (empty string for first page).
 */
export interface PageChangeEvent {
  /** Direction of navigation */
  direction: 'next' | 'previous' | 'first';
}

@Component({
  selector: 'app-pagination',
  standalone: true,
  imports: [RouterLink],
  template: `
    <nav class="flex items-center justify-between" aria-label="Pagination">
      <!-- Result count -->
      <p class="text-sm text-slate-600 dark:text-slate-400" i18n="@@pagination.showing">
        Showing
        <span class="font-medium">{{ startItem() }}</span>
        to
        <span class="font-medium">{{ endItem() }}</span>
        of
        <span class="font-medium">{{ total() }}</span>
        results
      </p>

      <!-- Page buttons -->
      <div class="flex items-center gap-2">
        @if (hasPrevious()) {
          <a
            [routerLink]="[]"
            [queryParams]="previousQueryParams()"
            queryParamsHandling="merge"
            (click)="onPrevious($event)"
            class="px-3 py-1.5 text-sm font-medium rounded-md border border-slate-300 dark:border-slate-600 text-slate-700 dark:text-slate-300 bg-white dark:bg-slate-700 hover:bg-slate-50 dark:hover:bg-slate-600 transition-colors cursor-pointer no-underline"
          >
            <span i18n="@@pagination.previous">Previous</span>
          </a>
        } @else {
          <span
            class="px-3 py-1.5 text-sm font-medium rounded-md border border-slate-300 dark:border-slate-600 text-slate-400 dark:text-slate-500 bg-white dark:bg-slate-700 opacity-50 cursor-not-allowed"
          >
            <span i18n="@@pagination.previous">Previous</span>
          </span>
        }

        <span class="text-sm text-slate-600 dark:text-slate-400" i18n="@@pagination.pageOf">
          Page {{ currentPage() }} of {{ totalPages() }}
        </span>

        @if (hasNext()) {
          <a
            [routerLink]="[]"
            [queryParams]="nextQueryParams()"
            queryParamsHandling="merge"
            (click)="onNext($event)"
            class="px-3 py-1.5 text-sm font-medium rounded-md border border-slate-300 dark:border-slate-600 text-slate-700 dark:text-slate-300 bg-white dark:bg-slate-700 hover:bg-slate-50 dark:hover:bg-slate-600 transition-colors cursor-pointer no-underline"
          >
            <span i18n="@@pagination.next">Next</span>
          </a>
        } @else {
          <span
            class="px-3 py-1.5 text-sm font-medium rounded-md border border-slate-300 dark:border-slate-600 text-slate-400 dark:text-slate-500 bg-white dark:bg-slate-700 opacity-50 cursor-not-allowed"
          >
            <span i18n="@@pagination.next">Next</span>
          </span>
        }
      </div>
    </nav>
  `,
})
export class PaginationComponent {
  /** Total number of items */
  total = input.required<number>();

  /** Number of items per page */
  limit = input.required<number>();

  /** Current page index (1-based) */
  page = input.required<number>();

  /** Whether there is a next page available */
  hasNext = input.required<boolean>();

  /** Whether there is a previous page available */
  hasPrevious = input.required<boolean>();

  /** Query params for the next page link */
  nextQueryParams = input<Record<string, string | null>>({});

  /** Query params for the previous page link */
  previousQueryParams = input<Record<string, string | null>>({});

  /** Emitted when the user navigates to a different page */
  pageChange = output<PageChangeEvent>();

  currentPage = computed(() => this.page());

  totalPages = computed(() => Math.max(1, Math.ceil(this.total() / this.limit())));

  startItem = computed(() => (this.total() === 0 ? 0 : (this.page() - 1) * this.limit() + 1));

  endItem = computed(() => Math.min(this.page() * this.limit(), this.total()));

  onPrevious(event: Event): void {
    event.preventDefault();
    this.pageChange.emit({ direction: 'previous' });
  }

  onNext(event: Event): void {
    event.preventDefault();
    this.pageChange.emit({ direction: 'next' });
  }
}

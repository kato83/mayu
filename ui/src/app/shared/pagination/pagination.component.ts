import { Component, computed, input, output } from '@angular/core';

@Component({
  selector: 'app-pagination',
  standalone: true,
  template: `
    <nav class="flex items-center justify-between" aria-label="Pagination">
      <!-- Result count -->
      <p class="text-sm text-slate-600 dark:text-slate-400">
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
        <button
          (click)="onPrevious()"
          [disabled]="currentPage() <= 1"
          class="px-3 py-1.5 text-sm font-medium rounded-md border border-slate-300 dark:border-slate-600 text-slate-700 dark:text-slate-300 bg-white dark:bg-slate-700 hover:bg-slate-50 dark:hover:bg-slate-600 disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
        >
          Previous
        </button>

        <span class="text-sm text-slate-600 dark:text-slate-400">
          Page {{ currentPage() }} of {{ totalPages() }}
        </span>

        <button
          (click)="onNext()"
          [disabled]="currentPage() >= totalPages()"
          class="px-3 py-1.5 text-sm font-medium rounded-md border border-slate-300 dark:border-slate-600 text-slate-700 dark:text-slate-300 bg-white dark:bg-slate-700 hover:bg-slate-50 dark:hover:bg-slate-600 disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
        >
          Next
        </button>
      </div>
    </nav>
  `,
})
export class PaginationComponent {
  /** Total number of items */
  total = input.required<number>();

  /** Number of items per page */
  limit = input.required<number>();

  /** Current offset (0-based) */
  offset = input.required<number>();

  /** Emitted when the user navigates to a different page */
  offsetChange = output<number>();

  currentPage = computed(() => Math.floor(this.offset() / this.limit()) + 1);

  totalPages = computed(() => Math.max(1, Math.ceil(this.total() / this.limit())));

  startItem = computed(() => (this.total() === 0 ? 0 : this.offset() + 1));

  endItem = computed(() => Math.min(this.offset() + this.limit(), this.total()));

  onPrevious(): void {
    const newOffset = Math.max(0, this.offset() - this.limit());
    this.offsetChange.emit(newOffset);
  }

  onNext(): void {
    const newOffset = this.offset() + this.limit();
    if (newOffset < this.total()) {
      this.offsetChange.emit(newOffset);
    }
  }
}

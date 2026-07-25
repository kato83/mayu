import { Component, inject, OnInit, signal, DestroyRef } from '@angular/core';
import { ActivatedRoute, RouterLink, RouterLinkActive } from '@angular/router';
import { takeUntilDestroyed } from '@angular/core/rxjs-interop';

import { DocsService } from './docs.service';
import { DOCS_MANIFEST, DocEntry } from './docs-manifest';
import { MarkdownPipe } from '../../shared/markdown.pipe';

@Component({
  selector: 'app-docs',
  imports: [RouterLink, RouterLinkActive, MarkdownPipe],
  template: `
    <div class="flex flex-col md:flex-row gap-6">
      <!-- Document list sidebar -->
      <nav class="w-full md:w-64 shrink-0">
        <h2 class="text-lg font-semibold text-slate-900 dark:text-slate-100 mb-3" i18n="@@docs.title">Documentation</h2>
        <ul class="space-y-1">
          @for (doc of documents; track doc.slug) {
            <li>
              <a
                [routerLink]="['/docs', doc.slug]"
                routerLinkActive="bg-indigo-50 dark:bg-indigo-900/30 text-indigo-700 dark:text-indigo-300"
                class="block px-3 py-2 rounded-md text-sm font-medium text-slate-700 dark:text-slate-300 hover:bg-slate-100 dark:hover:bg-slate-700 transition-colors"
              >
                {{ doc.title }}
              </a>
            </li>
          }
        </ul>
      </nav>

      <!-- Content area -->
      <div class="flex-1 min-w-0">
        @if (loading()) {
          <div class="flex items-center justify-center py-12">
            <p class="text-slate-500 dark:text-slate-400" i18n="@@docs.loading">Loading document...</p>
          </div>
        } @else if (error()) {
          <div class="rounded-md border border-red-300 dark:border-red-700 bg-red-50 dark:bg-red-900/20 p-4 text-sm text-red-800 dark:text-red-300">
            <p i18n="@@docs.error">Failed to load document.</p>
          </div>
        } @else {
          <article class="prose dark:prose-invert max-w-none" [innerHTML]="content() | markdown"></article>
        }
      </div>
    </div>
  `,
})
export class DocsComponent implements OnInit {
  private readonly route = inject(ActivatedRoute);
  private readonly docsService = inject(DocsService);
  private readonly destroyRef = inject(DestroyRef);

  readonly documents: DocEntry[] = DOCS_MANIFEST;

  content = signal('');
  loading = signal(false);
  error = signal<string | null>(null);

  ngOnInit(): void {
    this.route.params
      .pipe(takeUntilDestroyed(this.destroyRef))
      .subscribe((params) => {
        const slug = params['slug'] || 'readme';
        this.loadDocument(slug);
      });
  }

  private loadDocument(slug: string): void {
    this.loading.set(true);
    this.error.set(null);
    this.content.set('');

    this.docsService.getDocument(slug).subscribe({
      next: (md) => {
        this.content.set(md);
        this.loading.set(false);
      },
      error: () => {
        this.error.set('Failed to load document.');
        this.loading.set(false);
      },
    });
  }
}

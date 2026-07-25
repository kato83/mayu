import { Component, inject, OnInit, signal, DestroyRef } from '@angular/core';
import { ActivatedRoute, RouterLink, RouterLinkActive } from '@angular/router';
import { Title } from '@angular/platform-browser';
import { takeUntilDestroyed } from '@angular/core/rxjs-interop';
import { map, switchMap, catchError, of } from 'rxjs';

import { DocsService } from './docs.service';
import { DOCS_MANIFEST, DocEntry } from './docs-manifest';
import { MarkdownPipe } from '../../shared/markdown.pipe';

interface TocEntry {
  id: string;
  text: string;
  depth: number;
}

@Component({
  selector: 'app-docs',
  imports: [RouterLink, RouterLinkActive, MarkdownPipe],
  template: `
    <div class="flex flex-col md:flex-row gap-6">
      <!-- Document list sidebar -->
      <nav class="w-full md:w-64 shrink-0 md:sticky md:top-4 md:self-start">
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

        <!-- Table of Contents -->
        @if (toc().length > 0) {
          <div class="mt-6 border-t border-slate-200 dark:border-slate-700 pt-4">
            <h3 class="text-sm font-semibold text-slate-900 dark:text-slate-100 mb-2" i18n="@@docs.toc">Table of Contents</h3>
            <ul class="space-y-1 text-xs">
              @for (entry of toc(); track entry.id) {
                <li [style.padding-left.rem]="(entry.depth - 1) * 0.75">
                  <a
                    [href]="'#' + entry.id"
                    class="block py-1 text-slate-600 dark:text-slate-400 hover:text-indigo-600 dark:hover:text-indigo-400 transition-colors truncate"
                  >
                    {{ entry.text }}
                  </a>
                </li>
              }
            </ul>
          </div>
        }
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
  private readonly titleService = inject(Title);
  private readonly markdownPipe = new MarkdownPipe();

  readonly documents: DocEntry[] = DOCS_MANIFEST;

  content = signal('');
  loading = signal(false);
  error = signal<string | null>(null);
  toc = signal<TocEntry[]>([]);

  ngOnInit(): void {
    this.route.params
      .pipe(
        map((params) => params['slug'] || 'readme'),
        switchMap((slug) => {
          this.loading.set(true);
          this.error.set(null);
          this.content.set('');
          this.toc.set([]);
          return this.docsService.getDocument(slug).pipe(
            map((md) => ({ md, slug, failed: false })),
            catchError(() => of({ md: '', slug, failed: true })),
          );
        }),
        takeUntilDestroyed(this.destroyRef),
      )
      .subscribe(({ md, slug, failed }) => {
        if (failed) {
          this.error.set('Failed to load document.');
          this.loading.set(false);
        } else {
          const { body, title } = this.parseFrontmatter(md);
          const pageTitle = title || this.docsService.getEntry(slug)?.title || 'Docs';
          this.titleService.setTitle(`${pageTitle} - Mayu`);

          const rewritten = this.rewriteImagePaths(body, slug);
          this.content.set(rewritten);

          // Generate TOC from the rendered HTML
          const html = this.markdownPipe.transform(rewritten);
          this.toc.set(this.extractToc(html));

          this.loading.set(false);
        }
      });
  }

  /**
   * Parse YAML frontmatter from markdown content.
   * Extracts the `title` field if present and returns the body without frontmatter.
   */
  private parseFrontmatter(markdown: string): { body: string; title: string | null } {
    const frontmatterRegex = /^---\n([\s\S]*?)\n---\n?/;
    const match = markdown.match(frontmatterRegex);
    if (!match) {
      return { body: markdown, title: null };
    }

    const frontmatterBlock = match[1];
    const body = markdown.slice(match[0].length);

    // Simple YAML title extraction (no full YAML parser needed)
    const titleMatch = frontmatterBlock.match(/^title:\s*["']?(.+?)["']?\s*$/m);
    const title = titleMatch ? titleMatch[1] : null;

    return { body, title };
  }

  /**
   * Extract headings from rendered HTML to build a table of contents.
   */
  private extractToc(html: string): TocEntry[] {
    const entries: TocEntry[] = [];
    const headingRegex = /<h([1-6])\s+id="([^"]*)"[^>]*>(.*?)<\/h[1-6]>/g;
    let match: RegExpExecArray | null;

    while ((match = headingRegex.exec(html)) !== null) {
      const depth = parseInt(match[1], 10);
      const id = match[2];
      // Strip HTML tags from heading text
      const text = match[3].replace(/<[^>]*>/g, '');
      entries.push({ id, text, depth });
    }

    return entries;
  }

  private rewriteImagePaths(markdown: string, slug: string): string {
    const entry = this.docsService.getEntry(slug);
    if (!entry) {
      return markdown;
    }

    // Determine the base directory of the source markdown file
    const lastSlash = entry.filename.lastIndexOf('/');
    const baseDir = lastSlash >= 0 ? entry.filename.substring(0, lastSlash + 1) : '';

    // Rewrite relative image paths (Markdown image syntax)
    // Matches ![alt](path) where path is relative (not absolute and not a URL)
    return markdown.replace(
      /!\[([^\]]*)\]\((\.[^)]+)\)/g,
      (match, alt, relativePath) => {
        // Resolve the relative path against the base directory
        const resolved = this.resolveRelativePath(baseDir, relativePath);
        return `![${alt}](${resolved})`;
      },
    );
  }

  private resolveRelativePath(baseDir: string, relativePath: string): string {
    // Remove leading './' if present
    const cleaned = relativePath.startsWith('./') ? relativePath.substring(2) : relativePath;
    // Combine base directory with the relative path
    return baseDir + cleaned;
  }
}

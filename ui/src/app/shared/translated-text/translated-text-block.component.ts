import { Component, input, signal } from '@angular/core';
import { MarkdownPipe } from '../markdown.pipe';

/**
 * A block-level translated text component for longer content (details, descriptions).
 * Renders content as markdown and provides a toggle to switch between original and translated.
 *
 * Usage:
 * ```html
 * <app-translated-text-block [original]="d.details" [translated]="translation?.details" />
 * ```
 */
@Component({
  selector: 'app-translated-text-block',
  imports: [MarkdownPipe],
  template: `
    @if (translated() && original()) {
      <div class="relative">
        <div class="flex items-center justify-end mb-2">
          <button
            type="button"
            (click)="toggle()"
            [attr.aria-label]="showOriginal() ? labelShowTranslation : labelShowOriginal"
            class="inline-flex items-center gap-1 px-2 py-1 text-xs font-medium rounded border transition-colors cursor-pointer"
            [class]="showOriginal()
              ? 'bg-amber-50 dark:bg-amber-900/20 text-amber-700 dark:text-amber-400 border-amber-200 dark:border-amber-700 hover:bg-amber-100 dark:hover:bg-amber-900/40'
              : 'bg-indigo-50 dark:bg-indigo-900/20 text-indigo-600 dark:text-indigo-400 border-indigo-200 dark:border-indigo-700 hover:bg-indigo-100 dark:hover:bg-indigo-900/40'">
            <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 20 20" fill="currentColor" class="w-3.5 h-3.5">
              <path d="M7.75 2.75a.75.75 0 0 0-1.5 0v1.258a32.987 32.987 0 0 0-3.599.278.75.75 0 1 0 .198 1.487A31.545 31.545 0 0 1 8.7 5.545 19.381 19.381 0 0 1 7.257 9.75H2.759a.75.75 0 0 0 0 1.5h3.835a20.862 20.862 0 0 1-4.106 5.553.75.75 0 1 0 1.024 1.096A22.357 22.357 0 0 0 8 12.803a22.357 22.357 0 0 0 4.488 5.096.75.75 0 0 0 1.024-1.096 20.862 20.862 0 0 1-4.106-5.553h3.835a.75.75 0 0 0 0-1.5H8.743a19.39 19.39 0 0 1-1.443-4.205 31.561 31.561 0 0 1 5.851.228.75.75 0 0 0 .199-1.487 32.987 32.987 0 0 0-3.599-.278V2.75Z" />
              <path d="M13.75 9.25a.75.75 0 0 1 .707.5l2.354 6.633a.75.75 0 0 1-1.414.5l-.478-1.346h-2.838l-.478 1.346a.75.75 0 1 1-1.414-.5l2.354-6.633a.75.75 0 0 1 .707-.5Zm-.587 4.787h1.174l-.587-1.654-.587 1.654Z" />
            </svg>
            <span>{{ showOriginal() ? labelTranslated : labelOriginal }}</span>
          </button>
        </div>
        <div class="prose prose-sm dark:prose-invert max-w-none text-slate-700 dark:text-slate-300"
             [innerHTML]="(showOriginal() ? original() : translated()) | markdown">
        </div>
      </div>
    } @else if (original()) {
      <div class="prose prose-sm dark:prose-invert max-w-none text-slate-700 dark:text-slate-300"
           [innerHTML]="original() | markdown">
      </div>
    }
  `,
})
export class TranslatedTextBlockComponent {
  /** The original (source language) text (may contain markdown). */
  readonly original = input<string | undefined | null>();

  /** The translated text (may contain markdown). When provided, enables the toggle. */
  readonly translated = input<string | undefined | null>();

  /** Whether the original text is currently shown (toggle state). */
  readonly showOriginal = signal(false);

  readonly labelOriginal = $localize`:@@translatedText.original:Original`;
  readonly labelTranslated = $localize`:@@translatedText.translated:Translated`;
  readonly labelShowOriginal = $localize`:@@translatedText.showOriginal:Show original text`;
  readonly labelShowTranslation = $localize`:@@translatedText.showTranslation:Show translated text`;

  toggle(): void {
    this.showOriginal.update(v => !v);
  }
}

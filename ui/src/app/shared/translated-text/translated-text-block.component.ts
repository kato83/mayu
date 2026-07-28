import { Component, input, model } from '@angular/core';
import { MarkdownPipe } from '../markdown.pipe';

/**
 * Block-level translated text component for longer content (details, descriptions).
 * Renders content as markdown and provides a toggle to switch between original and translated.
 * When no translation exists, shows a translate request button.
 */
@Component({
  selector: 'app-translated-text-block',
  imports: [MarkdownPipe],
  template: `
    @if (translated()) {
      <!-- Translation available -->
      <div class="relative">
        <div class="flex items-center justify-end mb-2">
          <button
            type="button"
            (click)="showOriginal.set(!showOriginal())"
            class="inline-flex items-center gap-1 px-2 py-1 text-xs font-medium rounded border transition-colors cursor-pointer"
            [class]="showOriginal()
              ? 'bg-amber-50 dark:bg-amber-900/20 text-amber-700 dark:text-amber-400 border-amber-200 dark:border-amber-700 hover:bg-amber-100 dark:hover:bg-amber-900/40'
              : 'bg-indigo-50 dark:bg-indigo-900/20 text-indigo-600 dark:text-indigo-400 border-indigo-200 dark:border-indigo-700 hover:bg-indigo-100 dark:hover:bg-indigo-900/40'">
            <span>{{ showOriginal() ? labelTranslated : labelOriginal }}</span>
          </button>
        </div>
        <div class="prose prose-sm dark:prose-invert max-w-none text-slate-700 dark:text-slate-300"
             [innerHTML]="(showOriginal() ? original() : translated()) | markdown">
        </div>
      </div>
    } @else if (original()) {
      <!-- No translation: show original with optional translate button -->
      <div class="relative">
        @if (showTranslateButton()) {
          <div class="flex items-center justify-end mb-2">
            <button
              type="button"
              (click)="onTranslateRequest()"
              class="inline-flex items-center gap-1 px-2 py-1 text-xs font-medium rounded border transition-colors cursor-pointer bg-slate-50 dark:bg-slate-800 text-slate-500 dark:text-slate-400 border-slate-200 dark:border-slate-600 hover:bg-slate-100 dark:hover:bg-slate-700 hover:text-slate-700 dark:hover:text-slate-300">
              <span>{{ labelTranslate }}</span>
            </button>
          </div>
        }
        <div class="prose prose-sm dark:prose-invert max-w-none text-slate-700 dark:text-slate-300"
             [innerHTML]="original() | markdown">
        </div>
      </div>
    }
  `,
})
export class TranslatedTextBlockComponent {
  /** The original (source language) text (may contain markdown). */
  readonly original = input<string | undefined | null>();

  /** The translated text (may contain markdown). When provided, enables the toggle. */
  readonly translated = input<string | undefined | null>();

  /** Whether to show the translate request button when no translation exists. */
  readonly showTranslateButton = input(true);

  /** Two-way binding for the toggle state (allows parent global toggle control). */
  readonly showOriginal = model(false);

  /** Callback when translate is requested. */
  readonly translateRequested = input<(() => void) | undefined>();

  readonly labelOriginal = $localize`:@@translatedText.original:Original`;
  readonly labelTranslated = $localize`:@@translatedText.translated:Translated`;
  readonly labelTranslate = $localize`:@@translatedText.translate:Translate`;

  onTranslateRequest(): void {
    const fn = this.translateRequested();
    if (fn) fn();
  }
}

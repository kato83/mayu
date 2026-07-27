import { Component, input, model } from '@angular/core';

/**
 * Inline translated text component with toggle and translate-request support.
 *
 * Behavior:
 * - If `translated` is provided: shows translated text by default with a toggle to view original.
 * - If `translated` is NOT provided: shows original text with a "Translate" request button.
 * - The `showOriginal` model input allows parent to control toggle state (for global toggle).
 * - When the translate button is clicked, emits `translateRequest` output.
 */
@Component({
  selector: 'app-translated-text',
  template: `
    @if (translated()) {
      <!-- Translation available: show translated or original based on toggle -->
      <span class="translated-text-wrapper">
        <span>{{ showOriginal() ? original() : translated() }}</span>
        <button
          type="button"
          (click)="showOriginal.set(!showOriginal())"
          [attr.title]="showOriginal() ? labelShowTranslation : labelShowOriginal"
          class="inline-flex items-center ml-1.5 px-1.5 py-0.5 text-[10px] font-medium rounded border transition-colors cursor-pointer align-middle"
          [class]="showOriginal()
            ? 'bg-amber-50 dark:bg-amber-900/20 text-amber-700 dark:text-amber-400 border-amber-200 dark:border-amber-700 hover:bg-amber-100 dark:hover:bg-amber-900/40'
            : 'bg-indigo-50 dark:bg-indigo-900/20 text-indigo-600 dark:text-indigo-400 border-indigo-200 dark:border-indigo-700 hover:bg-indigo-100 dark:hover:bg-indigo-900/40'">
          {{ showOriginal() ? labelTranslated : labelOriginal }}
        </button>
      </span>
    } @else if (original()) {
      <!-- No translation: show original with translate request button -->
      <span class="translated-text-wrapper">
        <span>{{ original() }}</span>
        @if (showTranslateButton()) {
          <button
            type="button"
            (click)="onTranslateRequest()"
            [attr.title]="labelRequestTranslation"
            class="inline-flex items-center ml-1.5 px-1.5 py-0.5 text-[10px] font-medium rounded border transition-colors cursor-pointer align-middle bg-slate-50 dark:bg-slate-800 text-slate-500 dark:text-slate-400 border-slate-200 dark:border-slate-600 hover:bg-slate-100 dark:hover:bg-slate-700 hover:text-slate-700 dark:hover:text-slate-300">
            <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 16 16" fill="currentColor" class="w-3 h-3 mr-0.5">
              <path d="M6.8 2.4a.75.75 0 0 0-1.35 0l-2.7 5.4a.75.75 0 1 0 1.34.67L4.6 7.5h2.8l.51 .97a.75.75 0 1 0 1.34-.67l-2.7-5.4ZM5.35 6 6 4.7l.65 1.3h-1.3ZM12.5 10c0-.28-.22-.5-.5-.5H9a.5.5 0 0 0 0 1h1.27A4.46 4.46 0 0 1 8.9 12H8.5a.5.5 0 0 0 0 1h.4a4.49 4.49 0 0 1-1.4.88.5.5 0 0 0 .38.92A5.49 5.49 0 0 0 9.75 13a5.49 5.49 0 0 0 1.87 1.8.5.5 0 1 0 .51-.86A4.49 4.49 0 0 1 10.8 13h.7a4.46 4.46 0 0 0 .78-1.5H12a.5.5 0 0 0 0-1h-.5V10Z" />
            </svg>
            {{ labelTranslate }}
          </button>
        }
      </span>
    }
  `,
})
export class TranslatedTextComponent {
  /** The original (source language) text. */
  readonly original = input<string | undefined | null>();

  /** The translated text. When provided, enables the toggle. */
  readonly translated = input<string | undefined | null>();

  /** Whether to show the translate request button when no translation exists. */
  readonly showTranslateButton = input(true);

  /** Two-way binding for the toggle state (allows parent global toggle control). */
  readonly showOriginal = model(false);

  /** Callback when translate is requested. Parent should handle the API call. */
  readonly translateRequested = input<(() => void) | undefined>();

  readonly labelOriginal = $localize`:@@translatedText.original:Original`;
  readonly labelTranslated = $localize`:@@translatedText.translated:Translated`;
  readonly labelShowOriginal = $localize`:@@translatedText.showOriginal:Show original text`;
  readonly labelShowTranslation = $localize`:@@translatedText.showTranslation:Show translated text`;
  readonly labelTranslate = $localize`:@@translatedText.translate:Translate`;
  readonly labelRequestTranslation = $localize`:@@translatedText.requestTranslation:Request translation`;

  onTranslateRequest(): void {
    const fn = this.translateRequested();
    if (fn) fn();
  }
}

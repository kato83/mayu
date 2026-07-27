import { Component, input, signal } from '@angular/core';

/**
 * A component that displays translated text with a toggle to switch between
 * the translation and the original text.
 *
 * When a translation is available, the translated version is shown by default.
 * A small toggle button allows the user to switch to the original text and back.
 *
 * If no translation is provided, the original text is shown as-is without any toggle.
 *
 * Usage:
 * ```html
 * <app-translated-text [original]="d.summary" [translated]="translation?.summary" />
 * ```
 */
@Component({
  selector: 'app-translated-text',
  template: `
    @if (translated() && original()) {
      <span class="translated-text-wrapper">
        <span>{{ showOriginal() ? original() : translated() }}</span>
        <button
          type="button"
          (click)="toggle()"
          [attr.aria-label]="showOriginal() ? labelShowTranslation : labelShowOriginal"
          [attr.title]="showOriginal() ? labelShowTranslation : labelShowOriginal"
          class="inline-flex items-center ml-1.5 px-1.5 py-0.5 text-[10px] font-medium rounded border transition-colors cursor-pointer align-middle"
          [class]="showOriginal()
            ? 'bg-amber-50 dark:bg-amber-900/20 text-amber-700 dark:text-amber-400 border-amber-200 dark:border-amber-700 hover:bg-amber-100 dark:hover:bg-amber-900/40'
            : 'bg-indigo-50 dark:bg-indigo-900/20 text-indigo-600 dark:text-indigo-400 border-indigo-200 dark:border-indigo-700 hover:bg-indigo-100 dark:hover:bg-indigo-900/40'">
          {{ showOriginal() ? labelTranslated : labelOriginal }}
        </button>
      </span>
    } @else {
      <span>{{ original() }}</span>
    }
  `,
})
export class TranslatedTextComponent {
  /** The original (source language) text. */
  readonly original = input<string | undefined | null>();

  /** The translated text. When provided, enables the toggle. */
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

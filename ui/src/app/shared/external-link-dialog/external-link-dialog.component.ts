import { Component, ElementRef, viewChild, signal } from '@angular/core';

/**
 * A cushion dialog that warns users before navigating to an external site.
 * Uses the native HTML <dialog> element for proper modal behavior and accessibility.
 */
@Component({
  selector: 'app-external-link-dialog',
  standalone: true,
  template: `
    <dialog
      #dialog
      class="fixed inset-0 m-auto rounded-lg border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-800 shadow-xl p-0 w-full max-w-md max-h-fit backdrop:bg-black/50"
      (close)="onClose()"
    >
      <div class="p-6">
        <h2 class="text-lg font-semibold text-slate-900 dark:text-slate-100 mb-2" i18n="@@externalLink.title">
          Leaving this site
        </h2>
        <p class="text-sm text-slate-600 dark:text-slate-400 mb-4" i18n="@@externalLink.description">
          You are about to navigate to an external website. This link is not controlled by this application.
        </p>
        <div class="rounded-md bg-slate-50 dark:bg-slate-700/50 border border-slate-200 dark:border-slate-600 p-3 mb-5">
          <p class="text-xs text-slate-500 dark:text-slate-400 mb-1" i18n="@@externalLink.destination">Destination:</p>
          <p class="text-sm font-mono text-slate-800 dark:text-slate-200 break-all">{{ url() }}</p>
        </div>
        <div class="flex items-center justify-end gap-3">
          <button
            type="button"
            (click)="cancel()"
            class="px-4 py-2 text-sm font-medium text-slate-700 dark:text-slate-300 bg-slate-100 dark:bg-slate-700 hover:bg-slate-200 dark:hover:bg-slate-600 rounded-md transition-colors cursor-pointer"
            i18n="@@externalLink.cancel"
          >
            Cancel
          </button>
          <button
            type="button"
            (click)="proceed()"
            class="px-4 py-2 text-sm font-medium text-white bg-indigo-600 hover:bg-indigo-700 rounded-md transition-colors cursor-pointer"
            i18n="@@externalLink.proceed"
          >
            Open in new tab
          </button>
        </div>
      </div>
    </dialog>
  `,
})
export class ExternalLinkDialogComponent {
  private readonly dialogRef = viewChild.required<ElementRef<HTMLDialogElement>>('dialog');

  readonly url = signal('');

  /**
   * Opens the dialog with the given external URL.
   * Returns a promise that resolves to true if the user chooses to proceed.
   */
  open(url: string): Promise<boolean> {
    this.url.set(url);
    this.dialogRef().nativeElement.showModal();

    return new Promise<boolean>((resolve) => {
      this._resolve = resolve;
    });
  }

  cancel(): void {
    this._resolve?.(false);
    this._resolve = undefined;
    this.dialogRef().nativeElement.close();
  }

  proceed(): void {
    this._resolve?.(true);
    this._resolve = undefined;
    this.dialogRef().nativeElement.close();
  }

  onClose(): void {
    // Handle Escape key or other close mechanisms
    if (this._resolve) {
      this._resolve(false);
      this._resolve = undefined;
    }
  }

  private _resolve?: (value: boolean) => void;
}

import { Component, type ElementRef, signal, viewChild } from '@angular/core';

export interface ConfirmDialogOptions {
  title: string;
  message: string;
  confirmLabel?: string;
  cancelLabel?: string;
  destructive?: boolean;
}

/**
 * A reusable confirm dialog component using the native HTML <dialog> element.
 * Returns a Promise<boolean> indicating the user's choice.
 *
 * Usage:
 *   <app-confirm-dialog #confirmDialog />
 *   await this.confirmDialog.open({ title: '...', message: '...' })
 */
@Component({
  selector: 'app-confirm-dialog',
  standalone: true,
  template: `
    <dialog
      #dialog
      class="fixed inset-0 m-auto rounded-lg border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-800 shadow-xl p-0 w-[calc(100%-2rem)] max-w-md max-h-fit backdrop:bg-black/50"
      (close)="onClose()"
    >
      <div class="p-6">
        <h2 class="text-lg font-semibold text-slate-900 dark:text-slate-100 mb-2">
          {{ title() }}
        </h2>
        <p class="text-sm text-slate-600 dark:text-slate-400 mb-5">
          {{ message() }}
        </p>
        <div class="flex items-center justify-end gap-3">
          <button
            type="button"
            (click)="cancel()"
            class="px-4 py-2 text-sm font-medium text-slate-700 dark:text-slate-300 bg-slate-100 dark:bg-slate-700 hover:bg-slate-200 dark:hover:bg-slate-600 rounded-md transition-colors cursor-pointer"
          >
            {{ cancelLabel() }}
          </button>
          <button
            type="button"
            (click)="confirm()"
            class="px-4 py-2 text-sm font-medium text-white rounded-md transition-colors cursor-pointer"
            [class]="destructive() ? 'bg-red-600 hover:bg-red-700' : 'bg-indigo-600 hover:bg-indigo-700'"
          >
            {{ confirmLabel() }}
          </button>
        </div>
      </div>
    </dialog>
  `,
})
export class ConfirmDialogComponent {
  private readonly dialogRef = viewChild.required<ElementRef<HTMLDialogElement>>('dialog');

  readonly title = signal('');
  readonly message = signal('');
  readonly confirmLabel = signal('OK');
  readonly cancelLabel = signal('Cancel');
  readonly destructive = signal(false);

  /**
   * Opens the confirm dialog with the given options.
   * Returns a promise that resolves to true if the user confirms, false otherwise.
   */
  open(options: ConfirmDialogOptions): Promise<boolean> {
    this.title.set(options.title);
    this.message.set(options.message);
    this.confirmLabel.set(options.confirmLabel ?? 'OK');
    this.cancelLabel.set(options.cancelLabel ?? 'Cancel');
    this.destructive.set(options.destructive ?? false);
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

  confirm(): void {
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
